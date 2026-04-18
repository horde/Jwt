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

interface VerifierInterface
{
    /**
     * Return the JWA algorithm identifier this verifier handles.
     */
    public function algorithm(): string;

    /**
     * Verify that the raw binary signature is valid for the given data.
     */
    public function verify(string $data, string $signature): bool;
}
