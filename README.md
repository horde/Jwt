# Horde\Jwt

A standalone, zero-framework-dependency PHP library for creating, signing and
verifying JSON Web Tokens ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)).

Part of the [Horde Project](https://www.horde.org/).

## Features

- **HS256** (HMAC-SHA256) symmetric signing and verification
- **RS256** (RSA-SHA256) asymmetric signing and verification
- **ES256** (ECDSA P-256) asymmetric signing and verification
- Configurable claim validation: `exp`, `nbf`, `iss`, `aud` with clock skew
  leeway
- Typed key wrappers (`PrivateKey`, `PublicKey`) with PEM file/string loading
- JWK public key serialization ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517))
  for RSA and EC keys
- Clean `SignerInterface` / `VerifierInterface` abstractions for extending with
  additional algorithms
- PHP 8.1+, strict types, no external dependencies beyond `ext-openssl` and
  `ext-hash`

## Installation

```bash
composer require horde/jwt
```

## Quick Example

```php
use Horde\Jwt\Signer\Hs256Signer;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\Hs256Verifier;

$secret  = 'your-secret-key-at-least-32-bytes!';
$encoder = new TokenEncoder();
$decoder = new TokenDecoder();

// Sign
$token = $encoder->encode(['sub' => 'user123', 'iss' => 'myapp'], new Hs256Signer($secret));

// Verify
$verified = $decoder->decode($token->toString(), new Hs256Verifier($secret), [
    'verify_iss' => 'myapp',
]);

echo $verified->getSubject(); // 'user123'
```

See [doc/USAGE.md](doc/USAGE.md) for full documentation covering all
algorithms, key management, verification options and error handling.

## Heritage and Upgrading

This library extracts and generalizes JWT code that previously lived as
special-case implementations in:

- **[horde/core](https://github.com/horde/Core)**
  `Horde\Core\Auth\Jwt\Hs256Generator`, `Rs256Generator`, `JwtVerifier`,
  and related classes used for Horde session tokens
- **[horde/components](https://github.com/horde/components)**
  `Horde\Components\Auth\Rs256JwtGenerator` and GitHub App authentication
  wrappers

Those packages contained duplicated base64url encoding, key handling and
signing logic, with use-case-specific interfaces (GitHub App IDs, Horde
session conventions) that prevented reuse. `horde/jwt` replaces the
algorithmic layer with a general-purpose design while adding ES256 support,
typed key objects, JWK serialization and structured exceptions.

If you consumed the Core or Components JWT classes directly, see
[doc/UPGRADING.md](doc/UPGRADING.md) for a class-by-class migration guide.

The framework-level services (`JwtService`, `JwtServiceFactory`,
`JwtAuthMiddleware`, `GitHubAppAuthenticationService`) remain in their
respective packages and will be updated to delegate to `horde/jwt`.

## Relationship to horde/Oauth

[horde/Oauth](https://github.com/horde/Oauth) provides the OAuth protocol
implementation for the Horde framework. `horde/jwt` handles the token format
layer concerns such as creating and verifying JWTs. OAuth 2.0 and OpenID Connect
build upon this foundation. The two libraries are complementary:

- **horde/jwt**: token signing, verification, key management (this library)
- **horde/Oauth**: OAuth 2.0 authorization flows, token endpoints, OIDC
  discovery and protocol-level concerns

`horde/jwt` has no dependency on `horde/oauth` or any other Horde package.

## What This Library Is

- A general-purpose JWT signing and verification library
- A building block for OAuth 2.0, OpenID Connect, or any JWT-based protocol
- Usable standalone, outside the Horde framework

## What This Library Is Not

- Not an OAuth 2.0 or OpenID Connect implementation (see horde/oauth)
- Not a session management system (see `Horde\Core\Auth\Jwt\JwtService`)
- Not an HTTP middleware or authentication framework
- Not a JWKS endpoint server (it provides JWK *serialization*; serving JWKS
  over HTTP is an application concern)

## Relevant RFCs

- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) - JSON Web Token (JWT)
- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) - JSON Web Signature (JWS)
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) - JSON Web Encryption (JWE) *(not implemented)*
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) - JSON Web Key (JWK)
- [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) - JSON Web Algorithms (JWA)

## Requirements

- PHP 8.1 or later
- `ext-openssl`
- `ext-hash`

## License

LGPL-2.1-only. See [LICENSE](LICENSE) for details.
