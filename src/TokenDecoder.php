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

namespace Horde\Jwt;

use Horde\Jwt\Exception\ExpiredTokenException;
use Horde\Jwt\Exception\InvalidTokenException;
use Horde\Jwt\Token\VerifiedToken;
use Horde\Jwt\Verifier\VerifierInterface;
use JsonException;

final class TokenDecoder
{
    /**
     * Decode and verify a JWT.
     *
     * @param string $token The JWT string
     * @param VerifierInterface $verifier Algorithm implementation
     * @param array<string, mixed> $options Verification options:
     *   - 'leeway'     => int (default 0) — clock skew tolerance in seconds
     *   - 'verify_exp' => bool (default true) — check expiration
     *   - 'verify_nbf' => bool (default true) — check not-before
     *   - 'verify_iss' => string|null — required issuer value
     *   - 'verify_aud' => string|string[]|null — required audience value(s)
     * @return VerifiedToken
     * @throws InvalidTokenException on structure, signature, or claim failure
     * @throws ExpiredTokenException on expired token (subclass of InvalidTokenException)
     */
    public function decode(string $token, VerifierInterface $verifier, array $options = []): VerifiedToken
    {
        $leeway = (int) ($options['leeway'] ?? 0);
        $verifyExp = (bool) ($options['verify_exp'] ?? true);
        $verifyNbf = (bool) ($options['verify_nbf'] ?? true);
        $verifyIss = $options['verify_iss'] ?? null;
        $verifyAud = $options['verify_aud'] ?? null;

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('Invalid JWT structure: expected three dot-separated parts');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        $header = $this->decodeSegment($headerEncoded, 'header');
        $payload = $this->decodeSegment($payloadEncoded, 'payload');

        $alg = $header['alg'] ?? '';
        if ($alg !== $verifier->algorithm()) {
            throw new InvalidTokenException(
                "Algorithm mismatch: token uses '{$alg}', verifier expects '{$verifier->algorithm()}'"
            );
        }

        $signatureInput = "{$headerEncoded}.{$payloadEncoded}";
        $signature = Base64Url::decode($signatureEncoded);

        if (!$verifier->verify($signatureInput, $signature)) {
            throw new InvalidTokenException('Invalid signature');
        }

        $now = time();

        if ($verifyExp && isset($payload['exp'])) {
            if ($now >= ($payload['exp'] + $leeway)) {
                throw new ExpiredTokenException('Token has expired');
            }
        }

        if ($verifyNbf && isset($payload['nbf'])) {
            if ($now < ($payload['nbf'] - $leeway)) {
                throw new InvalidTokenException('Token is not yet valid');
            }
        }

        if ($verifyIss !== null) {
            if (!isset($payload['iss']) || $payload['iss'] !== $verifyIss) {
                throw new InvalidTokenException('Invalid issuer');
            }
        }

        if ($verifyAud !== null) {
            if (!isset($payload['aud'])) {
                throw new InvalidTokenException('Token missing audience claim');
            }
            $expectedAud = is_array($verifyAud) ? $verifyAud : [$verifyAud];
            $actualAud = is_array($payload['aud']) ? $payload['aud'] : [$payload['aud']];
            if (array_intersect($expectedAud, $actualAud) === []) {
                throw new InvalidTokenException('Invalid audience');
            }
        }

        return new VerifiedToken($token, $payload);
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeSegment(string $encoded, string $label): array
    {
        $json = Base64Url::decode($encoded);
        if ($json === '') {
            throw new InvalidTokenException("Invalid JWT {$label}: empty after decoding");
        }

        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidTokenException("Invalid JWT {$label}: " . $e->getMessage());
        }

        if (!is_array($data)) {
            throw new InvalidTokenException("Invalid JWT {$label}: expected JSON object");
        }

        return $data;
    }
}
