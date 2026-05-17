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

use RuntimeException;

final class Hs256Signer implements SignerInterface
{
    public function __construct(
        private readonly string $secret,
    ) {
        if (trim($secret) === '') {
            throw new RuntimeException('Secret cannot be empty');
        }
    }

    public function algorithm(): string
    {
        return 'HS256';
    }

    public function sign(string $data): string
    {
        return hash_hmac('sha256', $data, $this->secret, true);
    }
}
