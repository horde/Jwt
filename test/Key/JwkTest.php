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

use Horde\Jwt\Key\Jwk;
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
}
