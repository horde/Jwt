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

final class Rs256Signer implements SignerInterface
{
    public function __construct(
        private readonly PrivateKey $privateKey,
    ) {}

    public function algorithm(): string
    {
        return 'RS256';
    }

    public function sign(string $data): string
    {
        $signature = '';
        $success = openssl_sign($data, $signature, $this->privateKey->getResource(), OPENSSL_ALGO_SHA256);

        if (!$success) {
            throw new RuntimeException('RS256 signing failed: ' . openssl_error_string());
        }

        return $signature;
    }
}
