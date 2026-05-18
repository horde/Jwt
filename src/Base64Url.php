<?php

declare(strict_types=1);

/**
 * Base64url encoding and decoding (RFC 4648 section 5).
 *
 * This is a general-purpose encoding utility, not JWT-specific. It lives in
 * horde/jwt rather than horde/util so that horde/jwt stays dependency-free.
 * Other Horde packages (Core, Oauth, Secret) should use this class instead
 * of duplicating the logic in private methods.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 * @author   Torben Dannhauer <torben@dannhauer.de>
 */

namespace Horde\Jwt;

final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'), true) ?: '';
    }
}
