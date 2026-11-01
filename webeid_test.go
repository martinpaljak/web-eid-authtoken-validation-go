// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	webeid "github.com/martinpaljak/web-eid-authtoken-validation-go"
)

const (
	ria   = "https://ria.ee"
	ngrok = "https://47f0-46-131-86-189.ngrok-free.app"
	nonce = "12345678123456781234567812345678912356789123"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func parse(t *testing.T, name string) *webeid.AuthToken {
	t.Helper()
	tok, err := webeid.ParseAuthToken(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func fresh(value string) webeid.Nonce {
	return webeid.Nonce{Value: value, Expires: time.Now().Add(time.Minute)}
}

func TestVerify(t *testing.T) {
	for _, c := range []struct {
		file, origin, nonce string
		key                 x509.PublicKeyAlgorithm
	}{
		{"estonia-es384", ria, nonce, x509.ECDSA},
		{"estonia-es384-v11", ria, nonce, x509.ECDSA},
		{"latvia-rs256", ria, nonce, x509.RSA},
		{"finland-es384", ngrok, "x9qZDRO/ao2zprt3Z0bkW4CvvE/gALFtUIf3tcC0XxY=", x509.ECDSA},
		{"finland-ps256", ngrok, "ZqlDATkQRqh7LkqEbspBc2qDjot29oiNLlITdLgiVIo=", x509.RSA},
		{"belgium-es384", ngrok, "iMeEwP2cgUINY2XoO/lqEpOUn7z/ysHRqGXkGKC4VXE=", x509.ECDSA},
		{"belgium-rs256", ngrok, "YPVgYc7Qds0qmK/RilPLffnsIg7IIovM4BAWqGZWwiY=", x509.RSA},
	} {
		cert, err := parse(t, c.file).Verify(c.origin, fresh(c.nonce))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if cert.PublicKeyAlgorithm != c.key {
			t.Errorf("%s: key algorithm %v", c.file, cert.PublicKeyAlgorithm)
		}
	}

	cert, err := parse(t, "estonia-es384").Verify(ria, fresh(nonce))
	if err != nil || cert.Subject.CommonName != "J\u00d5EORG,JAAK-KRISTJAN,38001085718" {
		t.Fatalf("subject %v: %v", cert, err)
	}
	if v11 := parse(t, "estonia-es384-v11"); len(v11.UnverifiedSigningCertificates) != 1 || v11.UnverifiedSigningCertificates[0].Certificate.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("signing certificates %+v", v11.UnverifiedSigningCertificates)
	}

	type input struct {
		tok    webeid.AuthToken
		origin string
		nonce  webeid.Nonce
	}
	for name, c := range map[string]struct {
		edit func(*input)
		want error
	}{
		"wrong nonce":            {func(in *input) { in.nonce.Value = strings.Repeat("A", 44) }, webeid.ErrInvalidSignature},
		"wrong origin":           {func(in *input) { in.origin = "https://invalid.org" }, webeid.ErrInvalidSignature},
		"flipped signature":      {func(in *input) { in.tok.Signature = slices.Clone(in.tok.Signature); in.tok.Signature[9] ^= 1 }, webeid.ErrInvalidSignature},
		"truncated signature":    {func(in *input) { in.tok.Signature = in.tok.Signature[1:] }, webeid.ErrInvalidSignature},
		"RSA algorithm, EC key":  {func(in *input) { in.tok.Algorithm = "RS384" }, webeid.ErrInvalidSignature},
		"hash does not match":    {func(in *input) { in.tok.Algorithm = "ES256" }, webeid.ErrInvalidSignature},
		"empty nonce":            {func(in *input) { in.nonce = webeid.Nonce{} }, webeid.ErrNonceExpired},
		"expired nonce":          {func(in *input) { in.nonce.Expires = time.Now() }, webeid.ErrNonceExpired},
		"unsupported algorithm":  {func(in *input) { in.tok.Algorithm = "NONE" }, webeid.ErrInvalidToken},
		"format 10.0":            {func(in *input) { in.tok.Format = "web-eid:10.0" }, webeid.ErrInvalidToken},
		"format 1.00":            {func(in *input) { in.tok.Format = "web-eid:1.00" }, webeid.ErrInvalidToken},
		"format 01":              {func(in *input) { in.tok.Format = "web-eid:01" }, webeid.ErrInvalidToken},
		"format 1.":              {func(in *input) { in.tok.Format = "web-eid:1." }, webeid.ErrInvalidToken},
		"format 1.1.0":           {func(in *input) { in.tok.Format = "web-eid:1.1.0" }, webeid.ErrInvalidToken},
		"format 2":               {func(in *input) { in.tok.Format = "web-eid:2" }, webeid.ErrInvalidToken},
		"format 1":               {func(in *input) { in.tok.Format = "web-eid:1" }, webeid.ErrInvalidToken},
		"format 1.2, no lists":   {func(in *input) { in.tok.Format = "web-eid:1.2" }, webeid.ErrInvalidToken},
		"format 1.-1":            {func(in *input) { in.tok.Format = "web-eid:1.-1" }, webeid.ErrInvalidToken},
		"format 1.+1":            {func(in *input) { in.tok.Format = "web-eid:1.+1" }, webeid.ErrInvalidToken},
		"format overflow":        {func(in *input) { in.tok.Format = "web-eid:1.99999999999999999999" }, webeid.ErrInvalidToken},
		"missing certificate":    {func(in *input) { in.tok.UnverifiedCertificate = webeid.Certificate{} }, webeid.ErrInvalidToken},
		"missing signature":      {func(in *input) { in.tok.Signature = nil }, webeid.ErrInvalidToken},
		"origin with slash":      {func(in *input) { in.origin = ria + "/" }, nil},
		"origin with path":       {func(in *input) { in.origin = ria + "/path" }, nil},
		"origin without https":   {func(in *input) { in.origin = "http://ria.ee" }, nil},
		"origin with userinfo":   {func(in *input) { in.origin = "https://u@ria.ee" }, nil},
		"origin not punycode":    {func(in *input) { in.origin = "https://p\u00e4ike.ee" }, nil},
		"origin with empty host": {func(in *input) { in.origin = "https://" }, nil},
	} {
		in := input{*parse(t, "estonia-es384"), ria, fresh(nonce)}
		c.edit(&in)
		cert, err := in.tok.Verify(in.origin, in.nonce)
		switch {
		case cert != nil || err == nil:
			t.Errorf("%s: accepted", name)
		case c.want == nil && errors.Is(err, webeid.ErrInvalidSignature):
			t.Errorf("%s: origin not rejected before signature: %v", name, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestVerifyCertificate(t *testing.T) {
	const origin = "https://example.com"
	for name, c := range map[string]struct {
		curve elliptic.Curve
		alg   string
		hash  crypto.Hash
		usage x509.KeyUsage
		ext   []x509.ExtKeyUsage
		want  error
	}{
		"P-256 clientAuth":       {elliptic.P256(), "ES256", crypto.SHA256, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil},
		"P-384 no EKU":           {elliptic.P384(), "ES384", crypto.SHA384, x509.KeyUsageDigitalSignature, nil, nil},
		"P-521 clientAuth":       {elliptic.P521(), "ES512", crypto.SHA512, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}, nil},
		"non-repudiation key":    {elliptic.P384(), "ES384", crypto.SHA384, x509.KeyUsageContentCommitment, nil, webeid.ErrCertificatePurpose},
		"no key usage":           {elliptic.P384(), "ES384", crypto.SHA384, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, webeid.ErrCertificatePurpose},
		"EKU without clientAuth": {elliptic.P384(), "ES384", crypto.SHA384, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, webeid.ErrCertificatePurpose},
		"ES256 with P-384":       {elliptic.P384(), "ES256", crypto.SHA256, x509.KeyUsageDigitalSignature, nil, webeid.ErrInvalidSignature},
		"ES384 with P-256":       {elliptic.P256(), "ES384", crypto.SHA384, x509.KeyUsageDigitalSignature, nil, webeid.ErrInvalidSignature},
		"ES512 with P-256":       {elliptic.P256(), "ES512", crypto.SHA512, x509.KeyUsageDigitalSignature, nil, webeid.ErrInvalidSignature},
	} {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), KeyUsage: c.usage, ExtKeyUsage: c.ext}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		digest := func(parts ...[]byte) []byte {
			d := c.hash.New()
			for _, p := range parts {
				d.Write(p)
			}
			return d.Sum(nil)
		}
		r, s, err := ecdsa.Sign(rand.Reader, key, digest(digest([]byte(origin)), digest([]byte(nonce))))
		if err != nil {
			t.Fatal(err)
		}
		n := (c.curve.Params().BitSize + 7) / 8
		sig := make([]byte, 2*n)
		r.FillBytes(sig[:n])
		s.FillBytes(sig[n:])
		tok := webeid.AuthToken{UnverifiedCertificate: webeid.Certificate{Certificate: cert}, Algorithm: c.alg, Signature: sig, Format: "web-eid:1.0"}
		got, err := tok.Verify(origin, fresh(nonce))
		if !errors.Is(err, c.want) || (got == nil) != (c.want != nil) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestParseAuthToken(t *testing.T) {
	tok := parse(t, "estonia-es384")
	data, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), `{"unverifiedCertificate":"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBg`) {
		t.Errorf("marshaled as %.80s", data)
	}
	again, err := webeid.ParseAuthToken(data)
	if err != nil || !reflect.DeepEqual(tok, again) {
		t.Errorf("round trip: %v", err)
	}

	if data, err := json.Marshal(webeid.AuthToken{}); err != nil || string(data) != `{"unverifiedCertificate":null,"algorithm":"","signature":null,"format":""}` {
		t.Errorf("empty token marshaled as %s: %v", data, err)
	}

	with := func(file string, edit func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(fixture(t, file), &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		data, _ := json.Marshal(m)
		return data
	}
	set := func(file, field string, value any) []byte {
		return with(file, func(m map[string]any) { m[field] = value })
	}
	entry := func(edit func(e map[string]any)) []byte {
		return with("estonia-es384-v11", func(m map[string]any) { edit(m["unverifiedSigningCertificates"].([]any)[0].(map[string]any)) })
	}
	onlyIntermediates := with("estonia-es384-v11", func(m map[string]any) {
		m["unverifiedIntermediateCertificates"] = []any{m["unverifiedCertificate"]}
		delete(m, "unverifiedSigningCertificates")
	})
	if _, err := webeid.ParseAuthToken(onlyIntermediates); err != nil {
		t.Errorf("1.1 with intermediates only: %v", err)
	}
	if _, err := webeid.ParseAuthToken(set("estonia-es384-v11", "format", "web-eid:1.2")); err != nil {
		t.Errorf("1.2 with lists: %v", err)
	}
	for name, data := range map[string][]byte{
		"null":                        []byte("null"),
		"too short":                   []byte(strings.Repeat(" ", 99)),
		"too long":                    append(fixture(t, "estonia-es384"), strings.Repeat(" ", webeid.MaxAuthTokenLength)...),
		"not an object":               []byte(strings.Repeat("[]", 100)),
		"certificate not string":      set("estonia-es384", "unverifiedCertificate", 1),
		"certificate not base64":      set("estonia-es384", "unverifiedCertificate", "not base64!"),
		"certificate not DER":         set("estonia-es384", "unverifiedCertificate", "Z2FyYmFnZQ=="),
		"certificate null":            set("estonia-es384", "unverifiedCertificate", nil),
		"intermediate not DER":        set("estonia-es384-v11", "unverifiedIntermediateCertificates", []string{"Z2FyYmFnZQ=="}),
		"format missing":              set("estonia-es384", "format", ""),
		"algorithm missing":           set("estonia-es384", "algorithm", ""),
		"signature not base64":        set("estonia-es384", "signature", "@@@@"),
		"1.0 with signing list":       set("estonia-es384", "unverifiedSigningCertificates", []any{}),
		"1.0 with intermediate list":  set("estonia-es384", "unverifiedIntermediateCertificates", []any{}),
		"1.1 without lists":           set("estonia-es384-v11", "unverifiedSigningCertificates", nil),
		"1.1 empty signing list":      set("estonia-es384-v11", "unverifiedSigningCertificates", []any{}),
		"1.1 empty intermediate list": set("estonia-es384-v11", "unverifiedIntermediateCertificates", []any{}),
		"signing certificate missing": entry(func(e map[string]any) { delete(e, "certificate") }),
		"signing intermediates empty": entry(func(e map[string]any) { e["intermediateCertificates"] = []any{} }),
		"signing algorithms missing":  entry(func(e map[string]any) { delete(e, "supportedSignatureAlgorithms") }),
		"signing algorithm invalid": entry(func(e map[string]any) {
			e["supportedSignatureAlgorithms"] = []any{map[string]any{"cryptoAlgorithm": "ECC", "hashFunction": "SHA-256", "paddingScheme": "PSS"}}
		}),
	} {
		if tok, err := webeid.ParseAuthToken(data); tok != nil || !errors.Is(err, webeid.ErrInvalidToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewNonce(t *testing.T) {
	a, b := webeid.NewNonce(5*time.Minute), webeid.NewNonce(5*time.Minute)
	if len(a.Value) != 44 || a.Value == b.Value {
		t.Errorf("nonces %q %q", a.Value, b.Value)
	}
	if d := time.Until(a.Expires); d < 4*time.Minute || d > 5*time.Minute {
		t.Errorf("expires in %v", d)
	}
}
