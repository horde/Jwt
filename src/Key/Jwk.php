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
 * @author   Jean Charles Delépine <jean.charles.delepine@u-picardie.fr>
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
     * Deserialize a JWK to a PublicKey (RFC 7517).
     *
     * Supports RSA (kty=RSA, parameters n/e) and EC keys on curves
     * P-256, P-384 and P-521 (kty=EC, parameters crv/x/y).
     *
     * Typical use case: verifying JWTs signed by an external OIDC provider.
     * The provider's JWKS endpoint returns an array of JWK objects; pass each
     * one to this method to obtain a PublicKey suitable for Rs256Verifier or
     * Es256Verifier.
     *
     * @param array<string, mixed> $jwk A single JWK object (one entry from the
     *                                  'keys' array of a JWKS document)
     * @throws InvalidArgumentException on missing/invalid parameters or
     *                                  unsupported key type / EC curve
     */
    public static function toPublicKey(array $jwk): PublicKey
    {
        $kty = (string) ($jwk['kty'] ?? '');

        return match ($kty) {
            'RSA' => self::rsaJwkToPublicKey($jwk),
            'EC' => self::ecJwkToPublicKey($jwk),
            '' => throw new InvalidArgumentException('JWK missing required "kty" parameter'),
            default => throw new InvalidArgumentException(
                "Unsupported JWK key type '$kty'; only RSA and EC are supported"
            ),
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

    /**
     * @param array<string, mixed> $jwk
     */
    private static function rsaJwkToPublicKey(array $jwk): PublicKey
    {
        $n = $jwk['n'] ?? '';
        $e = $jwk['e'] ?? '';

        if ($n === '' || $e === '') {
            throw new InvalidArgumentException('RSA JWK missing required parameters "n" and/or "e"');
        }

        $modulus = self::base64UrlDecode($n);
        $exponent = self::base64UrlDecode($e);

        $encLen = static function (int $len): string {
            if ($len < 128) {
                return chr($len);
            }
            if ($len < 256) {
                return chr(0x81) . chr($len);
            }
            return chr(0x82) . chr($len >> 8) . chr($len & 0xff);
        };

        $encInt = static function (string $bytes) use ($encLen): string {
            if (ord($bytes[0]) > 0x7f) {
                $bytes = "\x00" . $bytes;
            }
            return "\x02" . $encLen(strlen($bytes)) . $bytes;
        };

        $inner = $encInt($modulus) . $encInt($exponent);
        $seq = "\x30" . $encLen(strlen($inner)) . $inner;
        $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $bitStr = "\x03" . $encLen(strlen($seq) + 1) . "\x00" . $seq;
        $spki = "\x30" . $encLen(strlen($algId) + strlen($bitStr)) . $algId . $bitStr;

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        return PublicKey::fromString($pem);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function ecJwkToPublicKey(array $jwk): PublicKey
    {
        $crv = (string) ($jwk['crv'] ?? '');
        $x = $jwk['x'] ?? '';
        $y = $jwk['y'] ?? '';

        if ($crv === '' || $x === '' || $y === '') {
            throw new InvalidArgumentException('EC JWK missing required parameters "crv", "x" and/or "y"');
        }

        $curveMap = [
            'P-256' => ['prime256v1', 32],
            'P-384' => ['secp384r1',  48],
            'P-521' => ['secp521r1',  66],
        ];

        if (!isset($curveMap[$crv])) {
            throw new InvalidArgumentException("Unsupported EC curve '$crv'; supported: P-256, P-384, P-521");
        }

        [$curveName, $coordSize] = $curveMap[$crv];

        $xBytes = str_pad(self::base64UrlDecode($x), $coordSize, "\x00", STR_PAD_LEFT);
        $yBytes = str_pad(self::base64UrlDecode($y), $coordSize, "\x00", STR_PAD_LEFT);

        $point = "\x04" . $xBytes . $yBytes;

        $oidMap = [
            'prime256v1' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
            'secp384r1' => "\x06\x05\x2b\x81\x04\x00\x22",
            'secp521r1' => "\x06\x05\x2b\x81\x04\x00\x23",
        ];

        $ecOid = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $curveOid = $oidMap[$curveName];
        $algSeq = "\x30" . chr(strlen($ecOid) + strlen($curveOid)) . $ecOid . $curveOid;

        $encLen = static function (int $len): string {
            if ($len < 128) {
                return chr($len);
            }
            if ($len < 256) {
                return chr(0x81) . chr($len);
            }
            return chr(0x82) . chr($len >> 8) . chr($len & 0xff);
        };

        $bitStr = "\x03" . $encLen(strlen($point) + 1) . "\x00" . $point;
        $spki = "\x30" . $encLen(strlen($algSeq) + strlen($bitStr)) . $algSeq . $bitStr;

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        return PublicKey::fromString($pem);
    }

    private static function base64UrlDecode(string $data): string
    {
        $padded = strtr($data, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $decoded = base64_decode($padded, strict: true);
        if ($decoded === false) {
            throw new InvalidArgumentException("Invalid base64url data: $data");
        }
        return $decoded;
    }
}
