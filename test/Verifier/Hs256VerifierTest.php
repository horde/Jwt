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

use Horde\Jwt\Verifier\Hs256Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(Hs256Verifier::class)]
class Hs256VerifierTest extends TestCase
{
    public function testAlgorithm(): void
    {
        $verifier = new Hs256Verifier('secret');
        $this->assertSame('HS256', $verifier->algorithm());
    }

    public function testAcceptsValidSignature(): void
    {
        $secret = 'my-secret';
        $data = 'test-data';
        $verifier = new Hs256Verifier($secret);

        $signature = hash_hmac('sha256', $data, $secret, true);
        $this->assertTrue($verifier->verify($data, $signature));
    }

    public function testRejectsInvalidSignature(): void
    {
        $verifier = new Hs256Verifier('secret');
        $this->assertFalse($verifier->verify('data', 'wrong-signature'));
    }

    public function testRejectsWrongSecret(): void
    {
        $data = 'test-data';
        $signature = hash_hmac('sha256', $data, 'secret-a', true);

        $verifier = new Hs256Verifier('secret-b');
        $this->assertFalse($verifier->verify($data, $signature));
    }

    public function testRejectsEmptySecret(): void
    {
        $this->expectException(RuntimeException::class);
        new Hs256Verifier('');
    }
}
