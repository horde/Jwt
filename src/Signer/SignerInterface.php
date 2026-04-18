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

interface SignerInterface
{
    /**
     * Return the JWA algorithm identifier (e.g. 'HS256', 'RS256', 'ES256').
     */
    public function algorithm(): string;

    /**
     * Sign the given data and return the raw binary signature.
     */
    public function sign(string $data): string;
}
