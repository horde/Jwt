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
 */

namespace Horde\Jwt\Test;

use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Signer\Es256Signer;
use Horde\Jwt\Signer\Hs256Signer;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\Token\GeneratedToken;
use Horde\Jwt\TokenEncoder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TokenEncoder::class)]
#[CoversClass(GeneratedToken::class)]
class TokenEncoderTest extends TestCase
{
    public function testHs256ProducesThreePartToken(): void
    {
        $encoder = new TokenEncoder();
        $signer = new Hs256Signer('test-secret-at-least-32-chars!!!');
        $token = $encoder->encode(['sub' => 'user1'], $signer);

        $parts = explode('.', $token->toString());
        $this->assertCount(3, $parts);
    }

    public function testAutoPopulatesIatAndExp(): void
    {
        $encoder = new TokenEncoder();
        $signer = new Hs256Signer('test-secret-at-least-32-chars!!!');
        $before = time();
        $token = $encoder->encode(['sub' => 'user1'], $signer, ttl: 3600);
        $after = time();

        $claims = $token->getClaims();
        $this->assertGreaterThanOrEqual($before, $claims['iat']);
        $this->assertLessThanOrEqual($after, $claims['iat']);
        $this->assertSame($claims['iat'] + 3600, $claims['exp']);
    }

    public function testRespectsExplicitExpAndIat(): void
    {
        $encoder = new TokenEncoder();
        $signer = new Hs256Signer('test-secret-at-least-32-chars!!!');
        $token = $encoder->encode(['iat' => 1000, 'exp' => 2000], $signer);

        $this->assertSame(1000, $token->getClaim('iat'));
        $this->assertSame(2000, $token->getClaim('exp'));
        $this->assertSame(2000, $token->getExpiresAt());
    }

    public function testRs256ProducesValidToken(): void
    {
        $key = $this->generateRsaKey();
        $encoder = new TokenEncoder();
        $token = $encoder->encode(['sub' => 'rs256-user'], new Rs256Signer($key));

        $parts = explode('.', $token->toString());
        $this->assertCount(3, $parts);
        $this->assertSame('rs256-user', $token->getClaim('sub'));
    }

    public function testEs256ProducesValidToken(): void
    {
        $key = $this->generateEcKey();
        $encoder = new TokenEncoder();
        $token = $encoder->encode(['sub' => 'es256-user'], new Es256Signer($key));

        $parts = explode('.', $token->toString());
        $this->assertCount(3, $parts);
        $this->assertSame('es256-user', $token->getClaim('sub'));
    }

    public function testToStringCast(): void
    {
        $encoder = new TokenEncoder();
        $signer = new Hs256Signer('test-secret-at-least-32-chars!!!');
        $token = $encoder->encode(['sub' => 'user1'], $signer);

        $this->assertSame($token->toString(), (string) $token);
    }

    private function generateRsaKey(): PrivateKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        return PrivateKey::fromString($pem);
    }

    private function generateEcKey(): PrivateKey
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $pem);
        return PrivateKey::fromString($pem);
    }
}
