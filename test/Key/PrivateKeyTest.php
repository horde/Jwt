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

namespace Horde\Jwt\Test\Key;

use Horde\Jwt\Key\PrivateKey;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PrivateKey::class)]
class PrivateKeyTest extends TestCase
{
    public function testFromStringWithRsa(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);

        $privateKey = PrivateKey::fromString($pem);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey->getResource());
    }

    public function testFromStringWithEc(): void
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $pem);

        $privateKey = PrivateKey::fromString($pem);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey->getResource());
    }

    public function testFromStringRejectsEmpty(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PrivateKey::fromString('');
    }

    public function testFromStringRejectsInvalidPem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PrivateKey::fromString('not a key');
    }

    public function testFromFileRejectsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PrivateKey::fromFile('/nonexistent/path.pem');
    }

    public function testGetPublicKeyPem(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);

        $privateKey = PrivateKey::fromString($pem);
        $publicPem = $privateKey->getPublicKeyPem();
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $publicPem);

        $pubResource = openssl_pkey_get_public($publicPem);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $pubResource);
    }
}
