<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 * @author   Torben Dannhauer <torben@dannhauer.de>
 * @author   Jean Charles Delépine <jean.charles.delepine@u-picardie.fr>
 */

namespace Horde\Jwt\Test\Key;

use Horde\Jwt\Exception\InvalidTokenException;
use Horde\Jwt\Key\Jwk;
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Es256Signer;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\Es256Verifier;
use Horde\Jwt\Verifier\Rs256Verifier;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Jwk::class)]
class JwkTest extends TestCase
{
    public function testRsaPublicKey(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($key);

        $jwk = Jwk::fromPublicKeyPem($details['key']);

        $this->assertSame('RSA', $jwk['kty']);
        $this->assertSame('sig', $jwk['use']);
        $this->assertArrayHasKey('n', $jwk);
        $this->assertArrayHasKey('e', $jwk);
    }

    public function testEcPublicKey(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = openssl_pkey_get_details($key);

        $jwk = Jwk::fromPublicKeyPem($details['key']);

        $this->assertSame('EC', $jwk['kty']);
        $this->assertSame('sig', $jwk['use']);
        $this->assertSame('P-256', $jwk['crv']);
        $this->assertArrayHasKey('x', $jwk);
        $this->assertArrayHasKey('y', $jwk);
    }

    public function testRejectsInvalidPem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Jwk::fromPublicKeyPem('not a key');
    }

    public function testRsaJwkRoundTrip(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privPem);
        $privKey = PrivateKey::fromString($privPem);
        $pubKey  = PublicKey::fromPrivateKey($privKey);

        $jwk         = Jwk::fromPublicKey($pubKey);
        $restoredKey = Jwk::toPublicKey($jwk);

        $this->assertInstanceOf(PublicKey::class, $restoredKey);

        $token    = (new TokenEncoder())->encode(['sub' => 'alice'], new Rs256Signer($privKey));
        $verified = (new TokenDecoder())->decode($token->toString(), new Rs256Verifier($restoredKey));

        $this->assertSame('alice', $verified->getSubject());
    }

    public function testEcP256JwkRoundTrip(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $privPem);
        $privKey = PrivateKey::fromString($privPem);
        $pubKey  = PublicKey::fromPrivateKey($privKey);

        $jwk         = Jwk::fromPublicKey($pubKey);
        $restoredKey = Jwk::toPublicKey($jwk);

        $this->assertInstanceOf(PublicKey::class, $restoredKey);

        $token    = (new TokenEncoder())->encode(['sub' => 'bob'], new Es256Signer($privKey));
        $verified = (new TokenDecoder())->decode($token->toString(), new Es256Verifier($restoredKey));

        $this->assertSame('bob', $verified->getSubject());
    }

    public function testEcP384JwkRoundTrip(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'secp384r1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $privPem);
        $privKey = PrivateKey::fromString($privPem);
        $pubKey  = PublicKey::fromPrivateKey($privKey);

        $jwk         = Jwk::fromPublicKey($pubKey);
        $restoredKey = Jwk::toPublicKey($jwk);

        $this->assertInstanceOf(PublicKey::class, $restoredKey);
    }

    public function testEcP521JwkRoundTrip(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'secp521r1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $privPem);
        $privKey = PrivateKey::fromString($privPem);
        $pubKey  = PublicKey::fromPrivateKey($privKey);

        $jwk         = Jwk::fromPublicKey($pubKey);
        $restoredKey = Jwk::toPublicKey($jwk);

        $this->assertInstanceOf(PublicKey::class, $restoredKey);
    }

    public function testRsaJwkWithExtraFieldsIgnored(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privPem);
        $jwk = array_merge(
            Jwk::fromPublicKey(PublicKey::fromPrivateKey(PrivateKey::fromString($privPem))),
            ['kid' => 'key-1', 'alg' => 'RS256']
        );

        $restoredKey = Jwk::toPublicKey($jwk);
        $this->assertInstanceOf(PublicKey::class, $restoredKey);
    }

    public function testWrongKeyCannotVerify(): void
    {
        $keyA = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $keyB = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($keyA, $privPemA);
        openssl_pkey_export($keyB, $privPemB);

        $privA = PrivateKey::fromString($privPemA);
        $privB = PrivateKey::fromString($privPemB);
        $pubB  = Jwk::toPublicKey(Jwk::fromPublicKey(PublicKey::fromPrivateKey($privB)));

        $token = (new TokenEncoder())->encode(['sub' => 'alice'], new Rs256Signer($privA));

        $this->expectException(InvalidTokenException::class);
        (new TokenDecoder())->decode($token->toString(), new Rs256Verifier($pubB));
    }

    public function testMissingKtyThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/missing required "kty"/i');

        Jwk::toPublicKey(['n' => 'abc', 'e' => 'AQAB']);
    }

    public function testUnsupportedKtyThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Unsupported JWK key type/i');

        Jwk::toPublicKey(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'abc']);
    }

    public function testRsaJwkMissingNThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/missing required parameters/i');

        Jwk::toPublicKey(['kty' => 'RSA', 'e' => 'AQAB']);
    }

    public function testRsaJwkMissingEThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/missing required parameters/i');

        Jwk::toPublicKey(['kty' => 'RSA', 'n' => 'abc123']);
    }

    public function testEcJwkMissingCrvThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/missing required parameters/i');

        Jwk::toPublicKey(['kty' => 'EC', 'x' => 'abc', 'y' => 'def']);
    }

    public function testEcJwkUnsupportedCurveThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Unsupported EC curve/i');

        Jwk::toPublicKey(['kty' => 'EC', 'crv' => 'P-224', 'x' => 'abc', 'y' => 'def']);
    }
}
