// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	webeid "github.com/martinpaljak/web-eid-authtoken-validation-go"
)

func TestSignatureEncoding(t *testing.T) {
	for _, c := range []struct {
		wire string
		want []byte
	}{
		{`"Zg=="`, []byte("f")},
		{`"Zm8="`, []byte("fo")},
		{`"Zm9v"`, []byte("foo")},
		{`"+/8="`, []byte{251, 255}},
		{`[102]`, nil},
		{`null`, nil},
		{`102`, nil},
		{`{}`, nil},
		{`true`, nil},
		{`"Zg"`, nil},
		{`"Zg="`, nil},
		{`"Zg==="`, nil},
		{`"Zh=="`, nil}, // Nonzero pad bits: permissive decoders return "f".
		{`"Zm9="`, nil}, // Nonzero pad bits: permissive decoders return "fo".
		{`"Zg==\n"`, nil},
		{`"Z\rg=="`, nil},
		{`" Zg=="`, nil},
		{`"-_8="`, nil},
	} {
		t.Run(c.wire, func(t *testing.T) {
			var response webeid.SignResponse
			err := json.Unmarshal([]byte(`{"signature":`+c.wire+`}`), &response)
			if c.want == nil {
				if err == nil {
					t.Fatal("invalid signing response encoding accepted")
				}
			} else if err != nil || !bytes.Equal(response.Signature, c.want) {
				t.Fatalf("decoded %x: %v", response.Signature, err)
			}

			var fields map[string]json.RawMessage
			if err := json.Unmarshal(fixture(t, "estonia-es384"), &fields); err != nil {
				t.Fatal(err)
			}
			fields["signature"] = json.RawMessage(c.wire)
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := webeid.ParseAuthToken(data)
			if c.want == nil {
				if tok != nil || !errors.Is(err, webeid.ErrInvalidToken) {
					t.Fatalf("invalid token encoding accepted: %v", err)
				}
			} else if err != nil || !bytes.Equal(tok.Signature, c.want) {
				t.Fatalf("valid token encoding rejected: %v", err)
			}
		})
	}
}

func TestCertificateEncoding(t *testing.T) {
	der := parse(t, "estonia-es384").UnverifiedCertificate.Raw
	// Use the complete valid DER to ensure array rejection is an encoding
	// check, rather than an incidental certificate parse failure.
	array := make([]int, len(der))
	for i, b := range der {
		array[i] = int(b)
	}
	for _, value := range []any{
		array, nil, base64.StdEncoding.EncodeToString(der) + "\n",
	} {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, document := range []string{
			`{"unverifiedCertificate":` + string(wire) + `}`,
			`{"unverifiedIntermediateCertificates":[` + string(wire) + `]}`,
			`{"unverifiedSigningCertificates":[{"certificate":` + string(wire) + `}]}`,
			`{"unverifiedSigningCertificates":[{"intermediateCertificates":[` + string(wire) + `]}]}`,
		} {
			var tok webeid.AuthToken
			if err := json.Unmarshal([]byte(document), &tok); err == nil {
				t.Fatal("invalid certificate encoding accepted")
			}
		}
		var cert webeid.SigningCertificate
		if err := json.Unmarshal([]byte(`{"certificate":`+string(wire)+`}`), &cert); err == nil {
			t.Fatal("invalid standalone signing certificate encoding accepted")
		}
	}
}
