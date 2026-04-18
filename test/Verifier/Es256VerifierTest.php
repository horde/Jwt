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
use Horde\Jwt\Verifier\Es256Verifier;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use OpenSSLAsymmetricKey;

#[CoversClass(Es256Verifier::class)]
class Es256VerifierTest extends TestCase
{
    public function testAlgorithm(): void
    {
        [$publicKey] = $this->generateEcKeyPair();
        $verifier = new Es256Verifier($publicKey);
        $this->assertSame('ES256', $verifier->algorithm());
    }

    public function testAcceptsValidP1363Signature(): void
    {
        [$publicKey, $privateKey] = $this->generateEcKeyPair();
        $verifier = new Es256Verifier($publicKey);

        $data = 'header.payload';
        openssl_sign($data, $derSig, $privateKey, OPENSSL_ALGO_SHA256);
        $p1363 = $this->derToP1363($derSig);

        $this->assertTrue($verifier->verify($data, $p1363));
    }

    public function testRejectsInvalidSignature(): void
    {
        [$publicKey] = $this->generateEcKeyPair();
        $verifier = new Es256Verifier($publicKey);

        $this->assertFalse($verifier->verify('data', str_repeat("\x00", 64)));
    }

    public function testRejectsWrongLength(): void
    {
        [$publicKey] = $this->generateEcKeyPair();
        $verifier = new Es256Verifier($publicKey);

        $this->expectException(InvalidArgumentException::class);
        $verifier->verify('data', 'too-short');
    }

    /**
     * @return array{PublicKey, OpenSSLAsymmetricKey}
     */
    private function generateEcKeyPair(): array
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = openssl_pkey_get_details($key);
        return [PublicKey::fromString($details['key']), $key];
    }

    private function derToP1363(string $der): string
    {
        $offset = 2;
        $rLen = ord($der[$offset + 1]);
        $r = substr($der, $offset + 2, $rLen);
        $offset += 2 + $rLen;
        $sLen = ord($der[$offset + 1]);
        $s = substr($der, $offset + 2, $sLen);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        return str_pad($r, 32, "\x00", STR_PAD_LEFT) . str_pad($s, 32, "\x00", STR_PAD_LEFT);
    }
}
