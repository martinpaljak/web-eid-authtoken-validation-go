// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// SignatureAlgorithm is the cryptoAlgorithm, hashFunction and paddingScheme triple of the Web eID protocol.
type SignatureAlgorithm struct {
	CryptoAlgorithm string `json:"cryptoAlgorithm"`
	HashFunction    string `json:"hashFunction"`
	PaddingScheme   string `json:"paddingScheme"`
}

// SigningCertificate is the getSigningCertificate response and an entry of AuthToken.UnverifiedSigningCertificates.
type SigningCertificate struct {
	Certificate                  Certificate          `json:"certificate"`
	IntermediateCertificates     []Certificate        `json:"intermediateCertificates,omitempty"`
	SupportedSignatureAlgorithms []SignatureAlgorithm `json:"supportedSignatureAlgorithms"`
}

// SignResponse is the response of the sign command.
type SignResponse struct {
	Signature          []byte             `json:"signature"`
	SignatureAlgorithm SignatureAlgorithm `json:"signatureAlgorithm"`
}

var hashes = map[string]crypto.Hash{
	"SHA-224":  crypto.SHA224,
	"SHA-256":  crypto.SHA256,
	"SHA-384":  crypto.SHA384,
	"SHA-512":  crypto.SHA512,
	"SHA3-224": crypto.SHA3_224,
	"SHA3-256": crypto.SHA3_256,
	"SHA3-384": crypto.SHA3_384,
	"SHA3-512": crypto.SHA3_512,
}

// Verify checks a 2048 to 8192 bit RSA or raw R||S ECDSA signature over digest with pub.
func (a SignatureAlgorithm) Verify(pub crypto.PublicKey, digest, signature []byte) error {
	h, ok := hashes[a.HashFunction]
	if !ok || len(digest) != h.Size() {
		return fmt.Errorf("%w: %d byte digest for %q", ErrInvalidSignature, len(digest), a.HashFunction)
	}
	err := errors.New("scheme does not match key")
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if a.CryptoAlgorithm == "ECC" && a.PaddingScheme == "NONE" {
			err = verifyECDSA(k, digest, signature)
		}
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n < 2048 || n > 8192 {
			err = fmt.Errorf("%d-bit RSA key", n)
			break
		}
		if a.CryptoAlgorithm == "RSA" && a.PaddingScheme == "PKCS1.5" {
			err = rsa.VerifyPKCS1v15(k, h, digest, signature)
		}
		if a.CryptoAlgorithm == "RSA" && a.PaddingScheme == "PSS" {
			err = rsa.VerifyPSS(k, h, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %s/%s/%s: %w", ErrInvalidSignature, a.CryptoAlgorithm, a.HashFunction, a.PaddingScheme, err)
	}
	return nil
}

func verifyECDSA(k *ecdsa.PublicKey, digest, signature []byte) error {
	n := (k.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*n {
		return fmt.Errorf("%d byte signature for %s", len(signature), k.Curve.Params().Name)
	}
	if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(signature[:n]), new(big.Int).SetBytes(signature[n:])) {
		return errors.New("verification failed")
	}
	return nil
}

// Verify checks the signature over digest made with the requested hashFunction and pub.
func (r SignResponse) Verify(pub crypto.PublicKey, hashFunction string, digest []byte) error {
	if r.SignatureAlgorithm.HashFunction != hashFunction {
		return fmt.Errorf("%w: %q signed as %q", ErrInvalidSignature, hashFunction, r.SignatureAlgorithm.HashFunction)
	}
	return r.SignatureAlgorithm.Verify(pub, digest, r.Signature)
}

func (a SignatureAlgorithm) valid() bool {
	_, ok := hashes[a.HashFunction]
	return ok && (a.CryptoAlgorithm == "ECC" && a.PaddingScheme == "NONE" || a.CryptoAlgorithm == "RSA" && (a.PaddingScheme == "PKCS1.5" || a.PaddingScheme == "PSS"))
}
