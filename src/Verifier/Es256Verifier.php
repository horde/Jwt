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

namespace Horde\Jwt\Verifier;

use Horde\Jwt\Key\PublicKey;
use InvalidArgumentException;

final class Es256Verifier implements VerifierInterface
{
    private const KEY_SIZE_BYTES = 32;

    public function __construct(
        private readonly PublicKey $publicKey,
    ) {}

    public function algorithm(): string
    {
        return 'ES256';
    }

    public function verify(string $data, string $signature): bool
    {
        $derSignature = self::p1363ToDer($signature, self::KEY_SIZE_BYTES);
        return openssl_verify($data, $derSignature, $this->publicKey->getResource(), OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * Convert IEEE P1363 fixed-length signature back to DER format
     * for OpenSSL verification.
     *
     * P1363: r (keySize bytes) || s (keySize bytes)
     * DER: SEQUENCE { INTEGER r, INTEGER s }
     */
    private static function p1363ToDer(string $p1363, int $keySize): string
    {
        if (strlen($p1363) !== 2 * $keySize) {
            throw new InvalidArgumentException('Invalid P1363 signature length');
        }

        $r = substr($p1363, 0, $keySize);
        $s = substr($p1363, $keySize);

        $r = ltrim($r, "\x00") ?: "\x00";
        $s = ltrim($s, "\x00") ?: "\x00";

        if (ord($r[0]) & 0x80) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) & 0x80) {
            $s = "\x00" . $s;
        }

        $rDer = "\x02" . chr(strlen($r)) . $r;
        $sDer = "\x02" . chr(strlen($s)) . $s;
        $sequence = $rDer . $sDer;

        return "\x30" . chr(strlen($sequence)) . $sequence;
    }
}
