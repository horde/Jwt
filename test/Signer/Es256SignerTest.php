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
use Horde\Jwt\Signer\Es256Signer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Es256Signer::class)]
class Es256SignerTest extends TestCase
{
    public function testAlgorithm(): void
    {
        $key = $this->generateEcKey();
        $signer = new Es256Signer($key);
        $this->assertSame('ES256', $signer->algorithm());
    }

    public function testSignProducesFixedLengthSignature(): void
    {
        $key = $this->generateEcKey();
        $signer = new Es256Signer($key);

        $signature = $signer->sign('header.payload');
        $this->assertSame(64, strlen($signature));
    }

    public function testSignatureIsConsistentLength(): void
    {
        $key = $this->generateEcKey();
        $signer = new Es256Signer($key);

        for ($i = 0; $i < 10; $i++) {
            $signature = $signer->sign('data-' . $i);
            $this->assertSame(64, strlen($signature), "Iteration {$i} produced wrong length");
        }
    }

    private function generateEcKey(): PrivateKey
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $pem);
        return PrivateKey::fromString($pem);
    }
}
