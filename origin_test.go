// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid_test

import (
	"errors"
	"testing"

	webeid "github.com/martinpaljak/web-eid-authtoken-validation-go"
)

func TestOrigin(t *testing.T) {
	// A valid token for ria.ee must reach signature verification for every
	// other canonical origin, and fail at the origin guard for invalid ones.
	tok := parse(t, "estonia-es384")
	for _, origin := range []string{
		"https://example.com", "https://example.com.", "https://localhost",
		"https://xn--pike-loa.ee", "https://my_site.example",
		"https://example.com:0", "https://example.com:8443", "https://example.com:65535",
		"https://127.0.0.1", "https://192.0.2.1:8443",
		"https://[::1]", "https://[2001:db8::1]:8443",
		"https://[::ffff:c000:201]", "https://[1:0:0:2::3]",
		"https://localhost:80",
		"http://localhost", "http://localhost.", "http://dev.localhost",
		"http://dev.app.localhost.", "http://localhost:3000", "http://localhost:443",
		"http://localhost:0", "http://localhost:65535",
		"http://127.0.0.0", "http://127.0.0.1", "http://127.42.10.20:8080",
		"http://127.255.255.255", "http://[::1]", "http://[::1]:8080",
	} {
		t.Run(origin, func(t *testing.T) {
			if _, err := tok.Verify(origin, fresh(nonce)); !errors.Is(err, webeid.ErrInvalidSignature) {
				t.Fatalf("canonical origin rejected before signature verification: %v", err)
			}
		})
	}
	for _, origin := range []string{
		"", "https:", "https://", "https:///example.com", "https://:443",
		"http://example.com", "HTTPS://example.com", "https://EXAMPLE.com",
		"https://example.com/", "https://example.com/path", "https://example.com?",
		"https://example.com?x=y", "https://example.com#", "https://example.com#fragment",
		"https://user@example.com", "https://example.com\\evil",
		"https://example.com:", "https://example.com:443", "https://example.com:0443",
		"https://example.com:08443", "https://example.com:65536", "https://example.com:99999",
		"https://example.com:-1", "https://example.com:+443", "https://example.com:port",
		"https://p\u00e4ike.ee", "https://%65xample.com",
		"https://exa mple.com", "https://example.com\n",
		"https://127.1", "https://2130706433", "https://0177.0.0.1",
		"https://0x7f000001", "https://127.0.0.1.", "https://127.000.0.1",
		"https://example.123", "https://example.0xff", "https://0x",
		"https://[0:0:0:0:0:0:0:1]", "https://[2001:DB8::1]",
		"https://[::ffff:192.0.2.1]", "https://[fe80::1%25en0]",
		"https://[127.0.0.1]", "https://[invalid]", "https://::1",
		"http:", "http://", "http://:80", "HTTP://localhost", "http://LOCALHOST",
		"http://localhost:80", "http://127.0.0.1:80", "http://[::1]:80",
		"http://localhost:", "http://localhost:03000", "http://localhost:65536",
		"http://localhost/", "http://localhost/path", "http://localhost?", "http://localhost#",
		"http://user@localhost", "http://localhost@evil.example", "http://localhost.evil.example",
		"http://notlocalhost", "http://localhost..", "http://dev.localhost..",
		"http://192.168.1.1", "http://0.0.0.0", "http://126.255.255.255", "http://128.0.0.0",
		"http://127.1", "http://2130706433", "http://0177.0.0.1", "http://0x7f000001",
		"http://127.0.0.1.", "http://[::]", "http://[::2]", "http://[::ffff:7f00:1]",
		"http://[0:0:0:0:0:0:0:1]", "http://[::1%25lo0]", "ftp://localhost", "file://localhost",
		"wss://example.com", "ws://localhost",
	} {
		t.Run(origin, func(t *testing.T) {
			cert, err := tok.Verify(origin, fresh(nonce))
			if cert != nil || err == nil || errors.Is(err, webeid.ErrInvalidSignature) {
				t.Fatalf("invalid origin passed the origin guard: %v", err)
			}
		})
	}
}
