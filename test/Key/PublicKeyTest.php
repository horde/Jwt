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
use Horde\Jwt\Key\PublicKey;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PublicKey::class)]
class PublicKeyTest extends TestCase
{
    public function testFromStringWithRsa(): void
    {
        $pem = $this->generateRsaPublicPem();
        $publicKey = PublicKey::fromString($pem);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $publicKey->getResource());
    }

    public function testFromStringWithEc(): void
    {
        $pem = $this->generateEcPublicPem();
        $publicKey = PublicKey::fromString($pem);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $publicKey->getResource());
    }

    public function testFromPrivateKey(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        $privateKey = PrivateKey::fromString($pem);

        $publicKey = PublicKey::fromPrivateKey($privateKey);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $publicKey->getPem());
    }

    public function testGetPem(): void
    {
        $pem = $this->generateRsaPublicPem();
        $publicKey = PublicKey::fromString($pem);
        $this->assertSame($pem, $publicKey->getPem());
    }

    public function testFromStringRejectsEmpty(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PublicKey::fromString('');
    }

    public function testFromStringRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PublicKey::fromString('not a key');
    }

    public function testFromFileRejectsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PublicKey::fromFile('/nonexistent/path.pem');
    }

    private function generateRsaPublicPem(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($key);
        return $details['key'];
    }

    private function generateEcPublicPem(): string
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = openssl_pkey_get_details($key);
        return $details['key'];
    }
}
