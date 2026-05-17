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

final class Rs256Verifier implements VerifierInterface
{
    public function __construct(
        private readonly PublicKey $publicKey,
    ) {}

    public function algorithm(): string
    {
        return 'RS256';
    }

    public function verify(string $data, string $signature): bool
    {
        return openssl_verify($data, $signature, $this->publicKey->getResource(), OPENSSL_ALGO_SHA256) === 1;
    }
}
