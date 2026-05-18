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

namespace Horde\Jwt\Test\Signer;

use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Signer\Rs256Signer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Rs256Signer::class)]
class Rs256SignerTest extends TestCase
{
    public function testAlgorithm(): void
    {
        $key = $this->generateRsaKey();
        $signer = new Rs256Signer($key);
        $this->assertSame('RS256', $signer->algorithm());
    }

    public function testSignProducesVerifiableSignature(): void
    {
        $key = $this->generateRsaKey();
        $signer = new Rs256Signer($key);
        $data = 'header.payload';

        $signature = $signer->sign($data);

        $pubKey = openssl_pkey_get_public($key->getPublicKeyPem());
        $this->assertSame(1, openssl_verify($data, $signature, $pubKey, OPENSSL_ALGO_SHA256));
    }

    private function generateRsaKey(): PrivateKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        return PrivateKey::fromString($pem);
    }
}
