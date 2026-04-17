<?php

/**
 * Example class for Jwt library.
 *
 * Copyright 2013-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category Horde
 * @package  Jwt
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */

declare(strict_types=1);

namespace Horde\Jwt;

/**
 * Example class for Jwt library.
 *
 * @category Horde
 * @package  Jwt
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */
class Example
{
    /**
     * Get a greeting message.
     *
     * @return string Greeting message
     */
    public function greet(): string
    {
        return 'Hello from Jwt!';
    }

    /**
     * Add two numbers.
     *
     * @param int $a First number
     * @param int $b Second number
     * @return int Sum of the numbers
     */
    public function add(int $a, int $b): int
    {
        return $a + $b;
    }
}
