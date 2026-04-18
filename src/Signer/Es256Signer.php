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

namespace Horde\Jwt\Signer;

use Horde\Jwt\Key\PrivateKey;
use RuntimeException;

final class Es256Signer implements SignerInterface
{
    private const KEY_SIZE_BYTES = 32;

    public function __construct(
        private readonly PrivateKey $privateKey,
    ) {}

    public function algorithm(): string
    {
        return 'ES256';
    }

    public function sign(string $data): string
    {
        $derSignature = '';
        $success = openssl_sign($data, $derSignature, $this->privateKey->getResource(), OPENSSL_ALGO_SHA256);

        if (!$success) {
            throw new RuntimeException('ES256 signing failed: ' . openssl_error_string());
        }

        return self::derToP1363($derSignature, self::KEY_SIZE_BYTES);
    }

    /**
     * Convert DER-encoded ECDSA signature to the fixed-length
     * IEEE P1363 format required by JWS (RFC 7515 §A.3).
     *
     * DER: SEQUENCE { INTEGER r, INTEGER s }
     * P1363: r (padded to keySize) || s (padded to keySize)
     */
    private static function derToP1363(string $der, int $keySize): string
    {
        $offset = 2;

        $rLength = ord($der[$offset + 1]);
        $r = substr($der, $offset + 2, $rLength);
        $offset += 2 + $rLength;

        $sLength = ord($der[$offset + 1]);
        $s = substr($der, $offset + 2, $sLength);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        return str_pad($r, $keySize, "\x00", STR_PAD_LEFT)
             . str_pad($s, $keySize, "\x00", STR_PAD_LEFT);
    }
}
