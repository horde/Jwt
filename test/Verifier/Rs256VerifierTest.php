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

namespace Horde\Jwt\Test\Verifier;

use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Verifier\Rs256Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use OpenSSLAsymmetricKey;

#[CoversClass(Rs256Verifier::class)]
class Rs256VerifierTest extends TestCase
{
    public function testAlgorithm(): void
    {
        [$publicKey] = $this->generateRsaKeyPair();
        $verifier = new Rs256Verifier($publicKey);
        $this->assertSame('RS256', $verifier->algorithm());
    }

    public function testAcceptsValidSignature(): void
    {
        [$publicKey, $privateKey] = $this->generateRsaKeyPair();
        $verifier = new Rs256Verifier($publicKey);

        $data = 'header.payload';
        openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $this->assertTrue($verifier->verify($data, $signature));
    }

    public function testRejectsInvalidSignature(): void
    {
        [$publicKey] = $this->generateRsaKeyPair();
        $verifier = new Rs256Verifier($publicKey);

        $this->assertFalse($verifier->verify('data', 'not-a-signature'));
    }

    public function testRejectsWrongKey(): void
    {
        [, $privateKey1] = $this->generateRsaKeyPair();
        [$publicKey2] = $this->generateRsaKeyPair();

        $data = 'header.payload';
        openssl_sign($data, $signature, $privateKey1, OPENSSL_ALGO_SHA256);

        $verifier = new Rs256Verifier($publicKey2);
        $this->assertFalse($verifier->verify($data, $signature));
    }

    /**
     * @return array{PublicKey, OpenSSLAsymmetricKey}
     */
    private function generateRsaKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($key);
        return [PublicKey::fromString($details['key']), $key];
    }
}
