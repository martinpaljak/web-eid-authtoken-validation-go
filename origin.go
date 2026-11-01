// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-License-Identifier: MIT

package webeid

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func validOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || (&url.URL{Scheme: u.Scheme, Host: u.Host}).String() != origin {
		return false
	}
	defaultPort := uint64(443)
	// W3C Secure Contexts section 3.1, steps 3-5:
	// https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy
	switch u.Scheme {
	case "https":
	case "http":
		if !localOriginHost(u.Hostname()) {
			return false
		}
		defaultPort = 80
	default:
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == defaultPort || strconv.FormatUint(n, 10) != port {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}

	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return false
		}
		canonical := ip.String()
		if ip.Is4In6() {
			// Browsers serialize mapped IPv4 addresses as hexadecimal IPv6,
			// whereas netip.String uses a dotted-decimal suffix.
			b := ip.As16()
			canonical = fmt.Sprintf("::ffff:%x:%x", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
		}
		return host == canonical
	}

	for _, c := range host {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("#%/:<>?@[\\]^|", c) {
			return false
		}
	}
	if host != strings.ToLower(host) {
		return false
	}

	// URL hosts ending in a number are parsed as IPv4 by browsers. Require
	// canonical dotted decimal, rejecting short, octal, hexadecimal, trailing
	// dot and overflowing forms rather than hashing a different origin.
	last := strings.TrimSuffix(host, ".")
	last = last[strings.LastIndexByte(last, '.')+1:]
	if allDigits(last, "0123456789") || strings.HasPrefix(last, "0x") &&
		(last == "0x" || allDigits(last[2:], "0123456789abcdef")) {
		ip, err := netip.ParseAddr(host)
		return err == nil && ip.Is4() && ip.String() == host
	}
	return true
}

// localOriginHost implements the loopback and localhost rules in W3C Secure
// Contexts section 3.1, steps 4-5: https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy
// The localhost rule assumes the user agent enforces loopback-only resolution
// (section 5.2). Server-side DNS resolution cannot establish that client-side property.
func localOriginHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		// IPv4-mapped IPv6 addresses are outside both specified CIDR ranges.
		return ip.Is4() && ip.IsLoopback() || ip == netip.IPv6Loopback()
	}
	return host == "localhost" || host == "localhost." ||
		strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".localhost.")
}

func allDigits(s, alphabet string) bool {
	return s != "" && strings.Trim(s, alphabet) == ""
}
