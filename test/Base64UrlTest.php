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

use Horde\Jwt\Base64Url;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Base64Url::class)]
class Base64UrlTest extends TestCase
{
    public function testEncodeDecodeRoundtrip(): void
    {
        $data = random_bytes(64);
        $this->assertSame($data, Base64Url::decode(Base64Url::encode($data)));
    }

    public function testNoPaddingOrUnsafeChars(): void
    {
        $data = hex2bin('fbff3e');
        $encoded = Base64Url::encode($data);
        $this->assertStringNotContainsString('=', $encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
    }

    public function testDecodeHandlesMissingPadding(): void
    {
        $original = 'hello world';
        $encoded = rtrim(base64_encode($original), '=');
        $encoded = strtr($encoded, '+/', '-_');
        $this->assertSame($original, Base64Url::decode($encoded));
    }

    public function testEmptyString(): void
    {
        $this->assertSame('', Base64Url::encode(''));
        $this->assertSame('', Base64Url::decode(''));
    }
}
