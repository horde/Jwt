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

final class Jwk
{
    /**
     * Serialize a PublicKey to JWK format (RFC 7517).
     *
     * @return array<string, string> JWK array with kty, algorithm-specific params, and use=sig
     */
    public static function fromPublicKey(PublicKey $publicKey): array
    {
        return self::fromPublicKeyPem($publicKey->getPem());
    }

    /**
     * Serialize an RSA or EC public key (PEM) to JWK format (RFC 7517).
     *
     * @return array<string, string> JWK array with kty, algorithm-specific params, and use=sig
     */
    public static function fromPublicKeyPem(string $pem): array
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new InvalidArgumentException('Invalid public key PEM: ' . openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new InvalidArgumentException('Failed to get key details');
        }

        return match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => self::rsaToJwk($details),
            OPENSSL_KEYTYPE_EC => self::ecToJwk($details),
            default => throw new InvalidArgumentException('Unsupported key type; only RSA and EC are supported'),
        };
    }

    /**
     * @return array<string, string>
     */
    private static function rsaToJwk(array $details): array
    {
        $rsa = $details['rsa'];
        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'n' => self::base64UrlEncodeInt($rsa['n']),
            'e' => self::base64UrlEncodeInt($rsa['e']),
        ];
    }

    /**
     * @return array<string, string>
     */
    private static function ecToJwk(array $details): array
    {
        $ec = $details['ec'];

        $curveMap = [
            'prime256v1' => 'P-256',
            'secp384r1' => 'P-384',
            'secp521r1' => 'P-521',
        ];

        $curveName = $ec['curve_name'] ?? '';
        $jwkCurve = $curveMap[$curveName] ?? throw new InvalidArgumentException("Unsupported EC curve: {$curveName}");

        return [
            'kty' => 'EC',
            'use' => 'sig',
            'crv' => $jwkCurve,
            'x' => self::base64UrlEncodeInt($ec['x']),
            'y' => self::base64UrlEncodeInt($ec['y']),
        ];
    }

    private static function base64UrlEncodeInt(string $binaryInt): string
    {
        return rtrim(strtr(base64_encode($binaryInt), '+/', '-_'), '=');
    }
}
