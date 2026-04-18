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

namespace Horde\Jwt\Token;

final class GeneratedToken
{
    public function __construct(
        private readonly string $token,
        private readonly int $expiresAt,
        private readonly array $claims = [],
    ) {}

    public function toString(): string
    {
        return $this->token;
    }

    public function __toString(): string
    {
        return $this->token;
    }

    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    public function isExpired(): bool
    {
        return time() >= $this->expiresAt;
    }

    public function getSecondsUntilExpiration(): int
    {
        return $this->expiresAt - time();
    }
}
