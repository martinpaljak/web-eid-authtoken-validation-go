// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// base64Bytes accepts only strings containing canonical, padded standard Base64.
// encoding/json's []byte decoder also accepts arrays, and its Base64 decoder
// ignores line breaks and nonzero pad bits.
type base64Bytes []byte

func (b *base64Bytes) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == nil || strings.ContainsAny(*s, "\r\n") {
		return errors.New("webeid: expected a Base64 string without line breaks")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(*s)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// UnmarshalJSON preserves the public []byte API while enforcing the wire format.
func (t *AuthToken) UnmarshalJSON(data []byte) error {
	type token AuthToken
	var decoded token
	wire := struct {
		*token
		Signature base64Bytes `json:"signature"`
	}{token: &decoded}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	decoded.Signature = wire.Signature
	*t = AuthToken(decoded)
	return nil
}

// UnmarshalJSON applies the same signature encoding rules to signing responses.
func (r *SignResponse) UnmarshalJSON(data []byte) error {
	type response SignResponse
	var decoded response
	wire := struct {
		*response
		Signature base64Bytes `json:"signature"`
	}{response: &decoded}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	decoded.Signature = wire.Signature
	*r = SignResponse(decoded)
	return nil
}
