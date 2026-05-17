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

final class VerifiedToken
{
    public function __construct(
        private readonly string $token,
        private readonly array $claims,
    ) {}

    public function toString(): string
    {
        return $this->token;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    public function hasClaim(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    public function getSubject(): ?string
    {
        $sub = $this->getClaim('sub');
        return is_string($sub) ? $sub : null;
    }

    public function getIssuer(): ?string
    {
        $iss = $this->getClaim('iss');
        return is_string($iss) ? $iss : null;
    }

    public function getAudience(): array|string|null
    {
        return $this->getClaim('aud');
    }

    public function getExpiration(): ?int
    {
        $exp = $this->getClaim('exp');
        return is_int($exp) ? $exp : null;
    }

    public function getIssuedAt(): ?int
    {
        $iat = $this->getClaim('iat');
        return is_int($iat) ? $iat : null;
    }

    public function isExpired(): bool
    {
        $exp = $this->getExpiration();
        if ($exp === null) {
            return false;
        }
        return time() >= $exp;
    }
}
