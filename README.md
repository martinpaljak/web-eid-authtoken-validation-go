# Go validation library for web-eid

[![Build status](https://github.com/martinpaljak/web-eid-authtoken-validation-go/actions/workflows/robot.yml/badge.svg?branch=main)](https://github.com/martinpaljak/web-eid-authtoken-validation-go/actions)

Verifies [Web eID](https://github.com/web-eid/web-eid-system-architecture-doc) authentication tokens and signatures in Go.

```go
token, err := webeid.ParseAuthToken(body)
if err != nil {
	return err
}
cert, err := token.Verify("https://example.com", nonce)
```

`Verify` returns the certificate that signed the origin and the nonce. It applies no trust policy: certificate validity, disallowed policies, the chain to your trust anchors, revocation and single-use nonce removal are your job.

## Origins

The origin you pass to `Verify` MUST be the browser's ASCII origin, byte for byte. Nothing gets normalized before hashing.

* Lowercase hostname, Punycode for IDN: `https://xn--pike-loa.ee`
* Canonical IP address: `https://192.0.2.1`, `https://[2001:db8::1]`
* No default port (443 for `https`, 80 for `http`): `https://example.com:8443`
* No path, trailing slash, user information, query or fragment

Allowed schemes:

| Scheme | Hosts | Example |
|--------|-------|---------|
| `https` | Any | `https://example.com` |
| `http` | `127.0.0.0/8`, `::1/128`, `localhost`, `localhost.`, `*.localhost`, `*.localhost.` | `http://localhost:3000`, `http://[::1]:8080` |

> [!NOTE]
> Local `http` is a deliberate choice, following [W3C Secure Contexts, section 3.1](https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy), steps 4-5. The [Web eID specification](https://github.com/web-eid/web-eid-system-architecture-doc#token-format) allows only `https`.

## Encoding

Certificate and signature JSON fields MUST be strings with padded standard Base64. Numeric arrays, `null`, Base64url, whitespace, line breaks and nonzero padding bits are rejected.
