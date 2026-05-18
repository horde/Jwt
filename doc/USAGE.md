# Horde\Jwt Usage

## Installation

```bash
composer require horde/jwt
```

Requires PHP 8.1+ with the `openssl` and `hash` extensions.

## Quick Start

### Signing a Token (HS256)

```php
use Horde\Jwt\Signer\Hs256Signer;
use Horde\Jwt\TokenEncoder;

$signer = new Hs256Signer('your-secret-key-at-least-32-bytes!');
$encoder = new TokenEncoder();

$token = $encoder->encode([
    'sub' => 'user123',
    'iss' => 'myapp',
], $signer);

echo $token->toString();            // The JWT string
echo $token->getExpiresAt();        // Unix timestamp
echo $token->isExpired();           // false
echo $token->getClaim('sub');       // 'user123'
```

### Verifying a Token (HS256)

```php
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\Verifier\Hs256Verifier;

$verifier = new Hs256Verifier('your-secret-key-at-least-32-bytes!');
$decoder = new TokenDecoder();

$verified = $decoder->decode($jwtString, $verifier);

echo $verified->getSubject();       // 'user123'
echo $verified->getIssuer();        // 'myapp'
echo $verified->getClaim('custom'); // any custom claim
echo $verified->hasClaim('sub');    // true
```

## Algorithms

### HS256 (HMAC-SHA256) - Symmetric

Both sides share the same secret. Best for server-to-server communication
where both parties are trusted.

```php
use Horde\Jwt\Signer\Hs256Signer;
use Horde\Jwt\Verifier\Hs256Verifier;

$secret = 'a-secret-at-least-256-bits-long!';
$signer   = new Hs256Signer($secret);
$verifier = new Hs256Verifier($secret);
```

### RS256 (RSA-SHA256) - Asymmetric

Sign with a private key, verify with the corresponding public key. Best when
the verifier should not be able to create tokens.

```php
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\Verifier\Rs256Verifier;

$privateKey = PrivateKey::fromFile('/path/to/private.pem');
$publicKey  = PublicKey::fromPrivateKey($privateKey);

$signer   = new Rs256Signer($privateKey);
$verifier = new Rs256Verifier($publicKey);
```

### ES256 (ECDSA P-256) - Asymmetric

Like RS256 but with smaller keys and signatures. Uses the NIST P-256 curve.

```php
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Es256Signer;
use Horde\Jwt\Verifier\Es256Verifier;

$privateKey = PrivateKey::fromFile('/path/to/ec-private.pem');
$publicKey  = PublicKey::fromPrivateKey($privateKey);

$signer   = new Es256Signer($privateKey);
$verifier = new Es256Verifier($publicKey);
```

## Token Encoding

`TokenEncoder::encode()` accepts a claims array, a signer and an optional
TTL (default 3600 seconds). It auto-populates `iat` (issued-at) and `exp`
(expiration) if not present in the claims array.

```php
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenEncoder;

$encoder = new TokenEncoder();

// Default TTL (1 hour)
$token = $encoder->encode(['sub' => 'alice'], $signer);

// Custom TTL (10 minutes)
$token = $encoder->encode(['sub' => 'alice'], $signer, ttl: 600);

// Explicit expiration (overrides TTL)
$token = $encoder->encode([
    'sub' => 'alice',
    'exp' => time() + 86400,  // 24 hours
], $signer);

// With standard claims
$token = $encoder->encode([
    'sub' => 'alice',
    'iss' => 'https://auth.example.com',
    'aud' => 'https://api.example.com',
    'jti' => bin2hex(random_bytes(16)),
], $signer);
```

The returned `GeneratedToken` provides:

- `toString()` / `__toString()` - the JWT string
- `getExpiresAt()` - expiration as Unix timestamp
- `getClaims()` - all claims as array
- `getClaim(string $name, mixed $default = null)` - single claim
- `isExpired()` - whether the token has expired
- `getSecondsUntilExpiration()` - seconds remaining (negative if expired)

## Token Decoding and Verification

`TokenDecoder::decode()` parses the JWT, verifies the signature, validates
standard claims and returns a `VerifiedToken`.

```php
use Horde\Jwt\TokenDecoder;

$decoder = new TokenDecoder();

// Basic verification (signature + expiration)
$verified = $decoder->decode($jwtString, $verifier);

// With issuer validation
$verified = $decoder->decode($jwtString, $verifier, [
    'verify_iss' => 'https://auth.example.com',
]);

// With audience validation
$verified = $decoder->decode($jwtString, $verifier, [
    'verify_aud' => 'https://api.example.com',
]);

// With clock skew tolerance
$verified = $decoder->decode($jwtString, $verifier, [
    'leeway' => 30,  // 30 seconds tolerance
]);

// Disable expiration check (e.g. for inspecting expired tokens)
$verified = $decoder->decode($jwtString, $verifier, [
    'verify_exp' => false,
]);
```

### Verification Options

| Option        | Type              | Default | Description                          |
|---------------|-------------------|---------|--------------------------------------|
| `leeway`      | `int`             | `0`     | Clock skew tolerance in seconds      |
| `verify_exp`  | `bool`            | `true`  | Check `exp` claim                    |
| `verify_nbf`  | `bool`            | `true`  | Check `nbf` (not-before) claim       |
| `verify_iss`  | `string\|null`    | `null`  | Required issuer value                |
| `verify_aud`  | `string\|null`    | `null`  | Required audience value              |

### VerifiedToken API

- `getSubject()` - `sub` claim (string or null)
- `getIssuer()` - `iss` claim (string or null)
- `getAudience()` - `aud` claim (string, array or null)
- `getExpiration()` - `exp` claim (int or null)
- `getIssuedAt()` - `iat` claim (int or null)
- `isExpired()` - whether current time is past `exp`
- `getClaim(string $name, mixed $default = null)` - any claim
- `hasClaim(string $name)` - whether a claim exists
- `getClaims()` - all claims as array
- `toString()` - the original JWT string

## Key Management

### PrivateKey

Load RSA or EC private keys from PEM files or strings:

```php
use Horde\Jwt\Key\PrivateKey;

$key = PrivateKey::fromFile('/path/to/private.pem');
$key = PrivateKey::fromString($pemString);

$key->getResource();       // OpenSSLAsymmetricKey
$key->getPem();            // PEM string
$key->getPublicKeyPem();   // extract corresponding public key PEM
```

### PublicKey

Load public keys or derive them from a private key:

```php
use Horde\Jwt\Key\PublicKey;

$pubKey = PublicKey::fromFile('/path/to/public.pem');
$pubKey = PublicKey::fromString($pemString);
$pubKey = PublicKey::fromPrivateKey($privateKey);

$pubKey->getResource();    // OpenSSLAsymmetricKey
$pubKey->getPem();         // PEM string
```

### JWK Serialization

Serialize public keys to JWK format (RFC 7517) for use in JWKS endpoints:

```php
use Horde\Jwt\Key\Jwk;
use Horde\Jwt\Key\PublicKey;

$publicKey = PublicKey::fromFile('/path/to/public.pem');
$jwk = Jwk::fromPublicKey($publicKey);
// Returns: ['kty' => 'RSA', 'use' => 'sig', 'n' => '...', 'e' => '...']

// Or directly from PEM:
$jwk = Jwk::fromPublicKeyPem($pemString);
```

Supported key types: RSA, EC (P-256, P-384, P-521).

## Error Handling

The library throws two exception types:

```php
use Horde\Jwt\Exception\ExpiredTokenException;
use Horde\Jwt\Exception\InvalidTokenException;

try {
    $verified = $decoder->decode($jwtString, $verifier);
} catch (ExpiredTokenException $e) {
    // Token signature was valid but has expired
    // ExpiredTokenException extends InvalidTokenException
} catch (InvalidTokenException $e) {
    // Malformed token, bad signature, wrong algorithm,
    // invalid issuer/audience or not-yet-valid (nbf)
}
```

`InvalidArgumentException` is thrown by key classes and verifiers for
invalid input (empty keys, wrong key formats, wrong signature lengths).

## Generating Keys

For testing or initial setup, generate keys with OpenSSL:

```bash
# RSA 2048-bit
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# EC P-256
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```
