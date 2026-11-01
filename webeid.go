// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

// Package webeid verifies Web eID authentication tokens and signatures without applying trust policy.
package webeid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidToken reports a malformed authentication token.
	ErrInvalidToken = errors.New("webeid: invalid authentication token")
	// ErrInvalidSignature reports a signature that does not verify.
	ErrInvalidSignature   = errors.New("webeid: invalid signature")
	ErrCertificatePurpose = errors.New("webeid: certificate not for client authentication")
	// ErrNonceExpired reports a missing or expired challenge nonce.
	ErrNonceExpired = errors.New("webeid: challenge nonce missing or expired")
)

// MaxAuthTokenLength is the size limit of ParseAuthToken in bytes.
const MaxAuthTokenLength = 65536

// Nonce is a single-use challenge to remove from the session store before Verify.
type Nonce struct {
	Value   string
	Expires time.Time
}

// NewNonce returns 32 random bytes in base64 that expire after ttl.
func NewNonce(ttl time.Duration) Nonce {
	b := make([]byte, 32)
	rand.Read(b)
	return Nonce{base64.StdEncoding.EncodeToString(b), time.Now().Add(ttl)}
}

// Certificate is an X.509 certificate carried in JSON as base64 DER.
type Certificate struct {
	*x509.Certificate
}

func (c *Certificate) UnmarshalJSON(data []byte) error {
	var der base64Bytes
	if err := json.Unmarshal(data, &der); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	c.Certificate = cert
	return nil
}

func (c Certificate) MarshalJSON() ([]byte, error) {
	if c.Certificate == nil {
		return []byte("null"), nil
	}
	return json.Marshal(c.Raw)
}

type AuthToken struct {
	UnverifiedCertificate              Certificate          `json:"unverifiedCertificate"`
	UnverifiedIntermediateCertificates []Certificate        `json:"unverifiedIntermediateCertificates,omitempty"`
	UnverifiedSigningCertificates      []SigningCertificate `json:"unverifiedSigningCertificates,omitempty"`
	Algorithm                          string               `json:"algorithm"`
	Signature                          []byte               `json:"signature"`
	Format                             string               `json:"format"`
	AppVersion                         string               `json:"appVersion,omitempty"`
}

var jwa = map[string]SignatureAlgorithm{
	"ES256": {"ECC", "SHA-256", "NONE"},
	"ES384": {"ECC", "SHA-384", "NONE"},
	"ES512": {"ECC", "SHA-512", "NONE"},
	"PS256": {"RSA", "SHA-256", "PSS"},
	"PS384": {"RSA", "SHA-384", "PSS"},
	"PS512": {"RSA", "SHA-512", "PSS"},
	"RS256": {"RSA", "SHA-256", "PKCS1.5"},
	"RS384": {"RSA", "SHA-384", "PKCS1.5"},
	"RS512": {"RSA", "SHA-512", "PKCS1.5"},
}

var curves = map[string]elliptic.Curve{
	"ES256": elliptic.P256(),
	"ES384": elliptic.P384(),
	"ES512": elliptic.P521(),
}

func minorVersion(format string) (int, bool) {
	s, ok := strings.CutPrefix(format, "web-eid:1.")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 0 && strconv.Itoa(n) == s
}

// ParseAuthToken decodes a JSON authentication token and checks its structure.
func ParseAuthToken(data []byte) (*AuthToken, error) {
	if len(data) < 100 || len(data) > MaxAuthTokenLength {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidToken, len(data))
	}
	var t AuthToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if _, err := t.check(); err != nil {
		return nil, err
	}
	return &t, nil
}

func (t *AuthToken) check() (SignatureAlgorithm, error) {
	alg, ok := jwa[t.Algorithm]
	minor, known := minorVersion(t.Format)
	switch {
	case !known:
		return alg, fmt.Errorf("%w: unsupported format %q", ErrInvalidToken, t.Format)
	case !ok:
		return alg, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidToken, t.Algorithm)
	case t.UnverifiedCertificate.Certificate == nil:
		return alg, fmt.Errorf("%w: missing certificate", ErrInvalidToken)
	case len(t.Signature) == 0:
		return alg, fmt.Errorf("%w: missing signature", ErrInvalidToken)
	case (t.UnverifiedIntermediateCertificates != nil || t.UnverifiedSigningCertificates != nil) != (minor >= 1):
		return alg, fmt.Errorf("%w: certificate lists do not match %s", ErrInvalidToken, t.Format)
	case empty(t.UnverifiedIntermediateCertificates) || empty(t.UnverifiedSigningCertificates):
		return alg, fmt.Errorf("%w: empty certificate list", ErrInvalidToken)
	}
	for _, s := range t.UnverifiedSigningCertificates {
		if s.Certificate.Certificate == nil || empty(s.IntermediateCertificates) || len(s.SupportedSignatureAlgorithms) == 0 {
			return alg, fmt.Errorf("%w: incomplete signing certificate", ErrInvalidToken)
		}
		for _, a := range s.SupportedSignatureAlgorithms {
			if !a.valid() {
				return alg, fmt.Errorf("%w: unsupported signature algorithm %+v", ErrInvalidToken, a)
			}
		}
	}
	return alg, nil
}

func empty[T any](list []T) bool {
	return list != nil && len(list) == 0
}

// Verify returns the certificate whose key signed nonce and the configured origin without judging its trust.
// Origin must already be the browser's canonical ASCII origin, without a trailing slash.
func (t *AuthToken) Verify(origin string, nonce Nonce) (*x509.Certificate, error) {
	if nonce.Value == "" || !time.Now().Before(nonce.Expires) {
		return nil, ErrNonceExpired
	}
	if !validOrigin(origin) {
		return nil, fmt.Errorf("webeid: origin %q must be canonical ASCII HTTPS or local HTTP", origin)
	}
	alg, err := t.check()
	if err != nil {
		return nil, err
	}
	cert := t.UnverifiedCertificate.Certificate
	if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && curves[t.Algorithm] != nil && k.Curve != curves[t.Algorithm] {
		return nil, fmt.Errorf("%w: %s with %s key", ErrInvalidSignature, t.Algorithm, k.Curve.Params().Name)
	}
	h := hashes[alg.HashFunction]
	digest := sum(h, sum(h, []byte(origin)), sum(h, []byte(nonce.Value)))
	if err := alg.Verify(cert.PublicKey, digest, t.Signature); err != nil {
		return nil, err
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		(len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) > 0 && !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)) {
		return nil, ErrCertificatePurpose
	}
	return cert, nil
}

func sum(h crypto.Hash, parts ...[]byte) []byte {
	d := h.New()
	for _, p := range parts {
		d.Write(p)
	}
	return d.Sum(nil)
}
