// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	webeid "github.com/martinpaljak/web-eid-authtoken-validation-go"
)

func TestSignatureAlgorithm(t *testing.T) {
	var keys []crypto.Signer
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys = append(keys, rsaKey)

	hashes := map[string]crypto.Hash{
		"SHA-224": crypto.SHA224, "SHA-256": crypto.SHA256, "SHA-384": crypto.SHA384, "SHA-512": crypto.SHA512,
		"SHA3-224": crypto.SHA3_224, "SHA3-256": crypto.SHA3_256, "SHA3-384": crypto.SHA3_384, "SHA3-512": crypto.SHA3_512,
	}
	for name, h := range hashes {
		d := h.New()
		d.Write([]byte("Hello, Web eID"))
		digest := d.Sum(nil)
		for _, key := range keys {
			var responses []webeid.SignResponse
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				r, s, err := ecdsa.Sign(rand.Reader, k, digest)
				if err != nil {
					t.Fatal(err)
				}
				n := (k.Curve.Params().BitSize + 7) / 8
				sig := make([]byte, 2*n)
				r.FillBytes(sig[:n])
				s.FillBytes(sig[n:])
				responses = append(responses, webeid.SignResponse{Signature: sig, SignatureAlgorithm: webeid.SignatureAlgorithm{CryptoAlgorithm: "ECC", HashFunction: name, PaddingScheme: "NONE"}})
			case *rsa.PrivateKey:
				pkcs, err := rsa.SignPKCS1v15(rand.Reader, k, h, digest)
				if err != nil {
					t.Fatal(err)
				}
				pss, err := rsa.SignPSS(rand.Reader, k, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				if err != nil {
					t.Fatal(err)
				}
				responses = append(responses,
					webeid.SignResponse{Signature: pkcs, SignatureAlgorithm: webeid.SignatureAlgorithm{CryptoAlgorithm: "RSA", HashFunction: name, PaddingScheme: "PKCS1.5"}},
					webeid.SignResponse{Signature: pss, SignatureAlgorithm: webeid.SignatureAlgorithm{CryptoAlgorithm: "RSA", HashFunction: name, PaddingScheme: "PSS"}})
			}
			for _, resp := range responses {
				data, err := json.Marshal(resp)
				if err != nil {
					t.Fatal(err)
				}
				var wire webeid.SignResponse
				if err := json.Unmarshal(data, &wire); err != nil {
					t.Fatal(err)
				}
				if err := wire.Verify(key.Public(), name, digest); err != nil {
					t.Errorf("%+v: %v", resp.SignatureAlgorithm, err)
				}
				if err := wire.Verify(key.Public(), "SHA-256", digest); name != "SHA-256" && !errors.Is(err, webeid.ErrInvalidSignature) {
					t.Errorf("%+v requested as SHA-256: %v", resp.SignatureAlgorithm, err)
				}
				bad := resp.SignatureAlgorithm
				for what, a := range map[string]webeid.SignatureAlgorithm{
					"crypto":  {CryptoAlgorithm: map[string]string{"ECC": "RSA", "RSA": "ECC"}[bad.CryptoAlgorithm], HashFunction: bad.HashFunction, PaddingScheme: bad.PaddingScheme},
					"padding": {CryptoAlgorithm: bad.CryptoAlgorithm, HashFunction: bad.HashFunction, PaddingScheme: map[string]string{"NONE": "PSS", "PSS": "PKCS1.5", "PKCS1.5": "PSS"}[bad.PaddingScheme]},
					"hash":    {CryptoAlgorithm: bad.CryptoAlgorithm, HashFunction: "SHA-1", PaddingScheme: bad.PaddingScheme},
				} {
					if err := a.Verify(key.Public(), digest, resp.Signature); !errors.Is(err, webeid.ErrInvalidSignature) {
						t.Errorf("%+v with wrong %s: %v", resp.SignatureAlgorithm, what, err)
					}
				}
				if err := bad.Verify(key.Public(), digest[1:], resp.Signature); !errors.Is(err, webeid.ErrInvalidSignature) {
					t.Errorf("%+v with short digest: %v", bad, err)
				}
				if err := bad.Verify(key.Public(), digest, resp.Signature[1:]); !errors.Is(err, webeid.ErrInvalidSignature) {
					t.Errorf("%+v with short signature: %v", bad, err)
				}
			}
		}
	}

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	weakSig, err := rsa.SignPKCS1v15(rand.Reader, weak, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	pkcs := webeid.SignatureAlgorithm{CryptoAlgorithm: "RSA", HashFunction: "SHA-256", PaddingScheme: "PKCS1.5"}
	if err := pkcs.Verify(&weak.PublicKey, digest, weakSig); !errors.Is(err, webeid.ErrInvalidSignature) {
		t.Errorf("1024-bit key: %v", err)
	}
	huge := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 8192, 1), E: 65537}
	if err := pkcs.Verify(huge, digest, make([]byte, 1025)); !errors.Is(err, webeid.ErrInvalidSignature) || !strings.Contains(err.Error(), "8193-bit") {
		t.Errorf("8193-bit key: %v", err)
	}

	edKey, _, _ := ed25519.GenerateKey(rand.Reader)
	ecc := webeid.SignatureAlgorithm{CryptoAlgorithm: "ECC", HashFunction: "SHA-256", PaddingScheme: "NONE"}
	if err := ecc.Verify(edKey, make([]byte, 32), make([]byte, 64)); !errors.Is(err, webeid.ErrInvalidSignature) {
		t.Errorf("ed25519 key: %v", err)
	}

	var cert webeid.SigningCertificate
	if err := json.Unmarshal(fixture(t, "estonia-es384"), &struct {
		Certificate *webeid.Certificate `json:"unverifiedCertificate"`
	}{&cert.Certificate}); err != nil || cert.Certificate.Certificate == nil {
		t.Fatalf("certificate: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"supportedSignatureAlgorithms":[{"cryptoAlgorithm":"ECC","hashFunction":"SHA-384","paddingScheme":"NONE"}]}`), &cert); err != nil || cert.SupportedSignatureAlgorithms[0] != (webeid.SignatureAlgorithm{CryptoAlgorithm: "ECC", HashFunction: "SHA-384", PaddingScheme: "NONE"}) {
		t.Errorf("supported algorithms %+v: %v", cert.SupportedSignatureAlgorithms, err)
	}
}
