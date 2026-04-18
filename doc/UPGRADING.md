# Upgrading to Horde\Jwt

## Heritage

`horde/jwt` extracts and generalizes JWT handling which previously existed as
special-case code in two Horde packages:

**`horde/core`** (`Horde\Core\Auth\Jwt\*`) contained:
- `Hs256Generator` HS256 token creation for Horde session tokens
- `Rs256Generator` RS256 token creation
- `JwtVerifier` HS256/RS256 verification with claim validation
- `PrivateKey` PEM private key wrapper
- `GeneratedJwt` / `VerifiedJwt` token value objects
- `JwtService` high-level Horde session token service
- `JwtServiceFactory` Horde injector factory
- `JwtAuthMiddleware` / `JwtSession` PSR-15 middleware

**`horde/components`** (`Horde\Components\Auth\*`) contained:
- `Rs256JwtGenerator` RS256 signing for GitHub App authentication
- `GitHubJwtGenerator` wrapper enforcing GitHub's 600-second TTL limit
- `PrivateKey` / `GeneratedJwt` duplicated value objects
- `GitHubAppAuthenticationService` GitHub App token lifecycle

Both packages duplicated base64url encoding, key handling and signing logic.
The `JwtGeneratorInterface` in each had a use-case-specific signature
(`int $appId` in Core vs GitHub-shaped constraints in Components) that prevented
polymorphic use across algorithms.

## What Changed

`horde/jwt` replaces the algorithmic layer with a general-purpose design:

| Old (Core / Components)                  | New (horde/jwt)                         |
|------------------------------------------|-----------------------------------------|
| `Hs256Generator::generate(array, string, int)` | `TokenEncoder::encode(array, Hs256Signer)` |
| `Rs256Generator::generate(int, PrivateKey, int)` | `TokenEncoder::encode(array, Rs256Signer)` |
| No ES256 support                         | `Es256Signer` / `Es256Verifier`        |
| `JwtVerifier::verifyHs256(string, string, array)` | `TokenDecoder::decode(string, Hs256Verifier)` |
| `JwtVerifier::verifyRs256(string, string, array)` | `TokenDecoder::decode(string, Rs256Verifier)` |
| `JwtGeneratorInterface` (app-ID-shaped)  | `SignerInterface` (algorithm-only)      |
| No verifier interface                    | `VerifierInterface`                     |
| `GeneratedJwt`                           | `GeneratedToken`                        |
| `VerifiedJwt`                            | `VerifiedToken`                         |
| `PrivateKey` (returns `resource`)        | `PrivateKey` (returns `OpenSSLAsymmetricKey`) |
| No `PublicKey` wrapper                   | `PublicKey` with `fromFile`, `fromString`, `fromPrivateKey` |
| Verifiers accept PEM strings             | Verifiers accept `PublicKey` objects    |
| Base64url duplicated in every class      | `Base64Url` static utility              |
| No JWK support                           | `Jwk::fromPublicKey()` (RFC 7517)      |

### API Design Differences

The old generators mixed use-case concerns into the interface:

```php
// Old Core - GitHub App ID baked into the interface
$generator->generate(int $appId, PrivateKey $key, int $expiry);

// Old Core - HS256 had a completely different signature
$generator->generate(array $claims, string $secret, int $expiry);
```

The new library separates algorithm choice from token construction:

```php
// New - algorithm is a property of the signer
$signer = new Rs256Signer($privateKey);
$token  = $encoder->encode(['iss' => (string) $appId], $signer, ttl: 540);

$signer = new Hs256Signer($secret);
$token  = $encoder->encode(['sub' => $userId], $signer);
```

## What Stays in Core and Components

`horde/jwt` is the algorithmic JWT library. The following remain in their
original packages because they depend on Horde framework services:

**Still in `horde/core`:**
- `JwtService` Horde session token service (uses Horde config, issuer
  conventions, access/refresh token patterns)
- `JwtServiceFactory` Horde injector integration
- `JwtAuthMiddleware` / `JwtSession` PSR-15 middleware wired to Horde
  session handling

**Still in `horde/components`:**
- `GitHubAppAuthenticationService` GitHub API token lifecycle, HTTP client
  integration, installation token caching
- `GitHubAppConfig` environment variable and config file loading
- `AuthenticationFactory` authentication method selection

These framework-level services will be updated to delegate to `horde/jwt` for
signing and verification, reducing them to thin adapters. During the transition
period the old algorithmic classes in Core and Components remain functional
alongside `horde/jwt`.

## Migration Guide for External Consumers

If you used `Horde\Core\Auth\Jwt\*` or `Horde\Components\Auth\*` classes
directly (outside of the Horde framework) this is how to migrate.

### 1. Add the Dependency

```bash
composer require horde/jwt
```

### 2. Replace Signing Code

**Before (Core HS256):**
```php
use Horde\Core\Auth\Jwt\Hs256Generator;

$generator = new Hs256Generator();
$jwt = $generator->generate(['sub' => $userId], $secret, 3600);
$tokenString = $jwt->token;
```

**After:**
```php
use Horde\Jwt\Signer\Hs256Signer;
use Horde\Jwt\TokenEncoder;

$signer = new Hs256Signer($secret);
$token = (new TokenEncoder())->encode(['sub' => $userId], $signer, ttl: 3600);
$tokenString = $token->toString();
```

**Before (Core/Components RS256):**
```php
use Horde\Core\Auth\Jwt\Rs256Generator;
use Horde\Core\Auth\Jwt\PrivateKey;

$key = PrivateKey::fromFile('/path/to/key.pem');
$generator = new Rs256Generator();
$jwt = $generator->generate($appId, $key, 600);
```

**After:**
```php
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;

$key = PrivateKey::fromFile('/path/to/key.pem');
$signer = new Rs256Signer($key);
$token = (new TokenEncoder())->encode(['iss' => (string) $appId], $signer, ttl: 600);
```

### 3. Replace Verification Code

**Before:**
```php
use Horde\Core\Auth\Jwt\JwtVerifier;

$verifier = new JwtVerifier();
$verified = $verifier->verifyHs256($tokenString, $secret, [
    'verify_iss' => 'myapp',
    'leeway' => 30,
]);
$userId = $verified->getSubject();
```

**After:**
```php
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\Verifier\Hs256Verifier;

$verifier = new Hs256Verifier($secret);
$verified = (new TokenDecoder())->decode($tokenString, $verifier, [
    'verify_iss' => 'myapp',
    'leeway' => 30,
]);
$userId = $verified->getSubject();
```

### 4. Replace Key Handling

**Before:**
```php
use Horde\Core\Auth\Jwt\PrivateKey;

$key = PrivateKey::fromFile('/path/to/key.pem');
$resource = $key->getResource();  // resource type in older PHP
```

**After:**
```php
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Key\PublicKey;

$key = PrivateKey::fromFile('/path/to/key.pem');
$resource = $key->getResource();  // OpenSSLAsymmetricKey

$pubKey = PublicKey::fromPrivateKey($key);
$verifier = new Rs256Verifier($pubKey);
```

### 5. Update Exception Handling

**Before:**
```php
use InvalidArgumentException;
use RuntimeException;

// Core threw generic InvalidArgumentException or RuntimeException
try {
    $verified = $verifier->verifyHs256($token, $secret);
} catch (InvalidArgumentException $e) {
    // could be expired, invalid or malformed
}
```

**After:**
```php
use Horde\Jwt\Exception\ExpiredTokenException;
use Horde\Jwt\Exception\InvalidTokenException;

try {
    $verified = $decoder->decode($token, $verifier);
} catch (ExpiredTokenException $e) {
    // specifically expired (valid signature, past exp)
} catch (InvalidTokenException $e) {
    // bad structure, signature, algorithm or claim mismatch
}
```

### 6. Class Name Mapping

| Old Class                                   | New Class                            |
|---------------------------------------------|--------------------------------------|
| `Horde\Core\Auth\Jwt\PrivateKey`            | `Horde\Jwt\Key\PrivateKey`           |
| `Horde\Components\Auth\PrivateKey`          | `Horde\Jwt\Key\PrivateKey`           |
| `Horde\Core\Auth\Jwt\GeneratedJwt`          | `Horde\Jwt\Token\GeneratedToken`     |
| `Horde\Components\Auth\GeneratedJwt`        | `Horde\Jwt\Token\GeneratedToken`     |
| `Horde\Core\Auth\Jwt\VerifiedJwt`           | `Horde\Jwt\Token\VerifiedToken`      |
| `Horde\Core\Auth\Jwt\Hs256Generator`        | `Horde\Jwt\Signer\Hs256Signer` + `TokenEncoder` |
| `Horde\Core\Auth\Jwt\Rs256Generator`        | `Horde\Jwt\Signer\Rs256Signer` + `TokenEncoder` |
| `Horde\Components\Auth\Rs256JwtGenerator`   | `Horde\Jwt\Signer\Rs256Signer` + `TokenEncoder` |
| `Horde\Core\Auth\Jwt\JwtVerifier`           | `Horde\Jwt\Verifier\*` + `TokenDecoder` |
| `Horde\Core\Auth\Jwt\JwtGeneratorInterface` | `Horde\Jwt\Signer\SignerInterface`   |
| *(no equivalent)*                           | `Horde\Jwt\Verifier\VerifierInterface` |
| *(no equivalent)*                           | `Horde\Jwt\Signer\Es256Signer`      |
| *(no equivalent)*                           | `Horde\Jwt\Verifier\Es256Verifier`  |
| *(no equivalent)*                           | `Horde\Jwt\Key\PublicKey`            |
| *(no equivalent)*                           | `Horde\Jwt\Key\Jwk`                 |
| *(no equivalent)*                           | `Horde\Jwt\Base64Url`               |

### 7. Behavioral Differences

- **`PrivateKey::getResource()`** now returns `OpenSSLAsymmetricKey` (PHP 8.0+
  type) instead of `resource`. If you type-checked with `is_resource()`, use
  `$key instanceof OpenSSLAsymmetricKey` instead.

- **`GeneratedToken`** uses methods (`toString()`, `getExpiresAt()`) rather
  than public readonly properties (`->token`, `->expiresAt`). If you accessed
  properties directly, switch to the getter methods. `GeneratedToken` also
  implements `__toString()` for string casting.

- **Token encoder auto-populates `iat` and `exp`** via the `??=` operator. If
  you pass these claims explicitly, your values are preserved. The old
  `Hs256Generator` and `Rs256Generator` always overwrote `iat`.

- **Verification is now split** by algorithm. Instead of calling
  `$verifier->verifyHs256()` or `$verifier->verifyRs256()`, construct the
  algorithm-specific verifier and call `$decoder->decode()`. The decoder
  checks that the token's `alg` header matches the verifier's algorithm and
  throws `InvalidTokenException` on mismatch.

- **RS256/ES256 verifiers accept `PublicKey` objects**, not raw PEM strings.
  Wrap your PEM with `PublicKey::fromString($pem)`.

- **No GitHub-specific constraints.** The old Components code enforced a
  600-second maximum TTL for GitHub App JWTs. `horde/jwt` does not enforce
  any maximum. If you need GitHub's limit, enforce it in your calling code.
