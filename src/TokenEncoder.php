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

namespace Horde\Jwt;

use Horde\Jwt\Signer\SignerInterface;
use Horde\Jwt\Token\GeneratedToken;

final class TokenEncoder
{
    /**
     * Encode claims into a signed JWT.
     *
     * Claims 'iat' and 'exp' are auto-populated if not provided.
     * Pass 'jti' in claims to set a token ID, or omit to leave it out.
     *
     * @param array<string, mixed> $claims JWT payload claims
     * @param SignerInterface $signer Algorithm implementation
     * @param int $ttl Time-to-live in seconds (used for 'exp' if not in claims)
     * @return GeneratedToken
     */
    public function encode(array $claims, SignerInterface $signer, int $ttl = 3600): GeneratedToken
    {
        $now = time();

        $claims['iat'] ??= $now;
        $claims['exp'] ??= $now + $ttl;

        $header = [
            'typ' => 'JWT',
            'alg' => $signer->algorithm(),
        ];

        $headerEncoded = Base64Url::encode(json_encode($header, JSON_THROW_ON_ERROR));
        $payloadEncoded = Base64Url::encode(json_encode($claims, JSON_THROW_ON_ERROR));

        $signatureInput = "{$headerEncoded}.{$payloadEncoded}";
        $signature = Base64Url::encode($signer->sign($signatureInput));

        $token = "{$signatureInput}.{$signature}";

        return new GeneratedToken($token, $claims['exp'], $claims);
    }
}
