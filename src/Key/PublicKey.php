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

namespace Horde\Jwt\Key;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;

final class PublicKey
{
    private function __construct(
        private readonly string $pem,
    ) {}

    public static function fromString(string $pem): self
    {
        if (trim($pem) === '') {
            throw new InvalidArgumentException('Public key content cannot be empty');
        }

        $resource = openssl_pkey_get_public($pem);
        if ($resource === false) {
            throw new InvalidArgumentException('Invalid public key format: ' . openssl_error_string());
        }

        return new self($pem);
    }

    public static function fromFile(string $filePath): self
    {
        if (!file_exists($filePath)) {
            throw new InvalidArgumentException("Public key file not found: {$filePath}");
        }

        if (!is_readable($filePath)) {
            throw new InvalidArgumentException("Public key file is not readable: {$filePath}");
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new InvalidArgumentException("Failed to read public key file: {$filePath}");
        }

        return self::fromString($content);
    }

    public static function fromPrivateKey(PrivateKey $privateKey): self
    {
        return self::fromString($privateKey->getPublicKeyPem());
    }

    public function getResource(): OpenSSLAsymmetricKey
    {
        $resource = openssl_pkey_get_public($this->pem);
        if ($resource === false) {
            throw new InvalidArgumentException('Failed to load public key: ' . openssl_error_string());
        }
        return $resource;
    }

    public function getPem(): string
    {
        return $this->pem;
    }
}
