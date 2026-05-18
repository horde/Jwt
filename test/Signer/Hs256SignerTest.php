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

use Horde\Jwt\Signer\Hs256Signer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(Hs256Signer::class)]
class Hs256SignerTest extends TestCase
{
    public function testAlgorithm(): void
    {
        $signer = new Hs256Signer('test-secret');
        $this->assertSame('HS256', $signer->algorithm());
    }

    public function testSignReturnsBinaryHmac(): void
    {
        $secret = 'my-secret-key';
        $signer = new Hs256Signer($secret);
        $data = 'header.payload';

        $signature = $signer->sign($data);

        $expected = hash_hmac('sha256', $data, $secret, true);
        $this->assertSame($expected, $signature);
    }

    public function testDifferentDataProducesDifferentSignatures(): void
    {
        $signer = new Hs256Signer('secret');
        $this->assertNotSame($signer->sign('data1'), $signer->sign('data2'));
    }

    public function testRejectsEmptySecret(): void
    {
        $this->expectException(RuntimeException::class);
        new Hs256Signer('');
    }
}
