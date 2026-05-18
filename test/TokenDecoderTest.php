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

namespace Horde\Jwt\Test;

use Horde\Jwt\Exception\ExpiredTokenException;
use Horde\Jwt\Exception\InvalidTokenException;
use Horde\Jwt\Key\PrivateKey;
use Horde\Jwt\Key\PublicKey;
use Horde\Jwt\Signer\Es256Signer;
use Horde\Jwt\Signer\Hs256Signer;
use Horde\Jwt\Signer\Rs256Signer;
use Horde\Jwt\Token\VerifiedToken;
use Horde\Jwt\TokenDecoder;
use Horde\Jwt\TokenEncoder;
use Horde\Jwt\Verifier\Es256Verifier;
use Horde\Jwt\Verifier\Hs256Verifier;
use Horde\Jwt\Verifier\Rs256Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TokenDecoder::class)]
#[CoversClass(VerifiedToken::class)]
#[CoversClass(InvalidTokenException::class)]
#[CoversClass(ExpiredTokenException::class)]
class TokenDecoderTest extends TestCase
{
    private TokenEncoder $encoder;
    private TokenDecoder $decoder;

    protected function setUp(): void
    {
        $this->encoder = new TokenEncoder();
        $this->decoder = new TokenDecoder();
    }

    public function testHs256RoundTrip(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['sub' => 'alice', 'iss' => 'test'], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier);

        $this->assertSame('alice', $verified->getSubject());
        $this->assertSame('test', $verified->getIssuer());
        $this->assertFalse($verified->isExpired());
    }

    public function testRs256RoundTrip(): void
    {
        $key = $this->generateRsaKey();
        $signer = new Rs256Signer($key);
        $verifier = new Rs256Verifier(PublicKey::fromPrivateKey($key));

        $token = $this->encoder->encode(['sub' => 'bob', 'aud' => 'myapp'], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier);

        $this->assertSame('bob', $verified->getSubject());
        $this->assertSame('myapp', $verified->getAudience());
    }

    public function testEs256RoundTrip(): void
    {
        $key = $this->generateEcKey();
        $signer = new Es256Signer($key);
        $verifier = new Es256Verifier(PublicKey::fromPrivateKey($key));

        $token = $this->encoder->encode(['sub' => 'carol'], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier);

        $this->assertSame('carol', $verified->getSubject());
    }

    public function testRejectsExpiredToken(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['exp' => time() - 10], $signer);

        $this->expectException(ExpiredTokenException::class);
        $this->decoder->decode($token->toString(), $verifier);
    }

    public function testLeewayAllowsSlightlyExpired(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['exp' => time() - 5], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier, ['leeway' => 10]);

        $this->assertInstanceOf(VerifiedToken::class, $verified);
    }

    public function testRejectsNotYetValidToken(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['nbf' => time() + 3600], $signer);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('not yet valid');
        $this->decoder->decode($token->toString(), $verifier);
    }

    public function testVerifiesIssuer(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['iss' => 'wrong-issuer'], $signer);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('issuer');
        $this->decoder->decode($token->toString(), $verifier, ['verify_iss' => 'expected-issuer']);
    }

    public function testVerifiesAudience(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['aud' => 'other-app'], $signer);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('audience');
        $this->decoder->decode($token->toString(), $verifier, ['verify_aud' => 'my-app']);
    }

    public function testAcceptsMatchingAudienceFromArray(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['aud' => ['app1', 'app2']], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier, ['verify_aud' => 'app2']);

        $this->assertSame(['app1', 'app2'], $verified->getAudience());
    }

    public function testRejectsMalformedToken(): void
    {
        $verifier = new Hs256Verifier('secret');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('three');
        $this->decoder->decode('not.a.valid.jwt.at.all', $verifier);
    }

    public function testRejectsTamperedPayload(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['sub' => 'alice'], $signer);
        $parts = explode('.', $token->toString());
        $parts[1] = \Horde\Jwt\Base64Url::encode(json_encode(['sub' => 'eve', 'iat' => time(), 'exp' => time() + 3600]));
        $tampered = implode('.', $parts);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('signature');
        $this->decoder->decode($tampered, $verifier);
    }

    public function testRejectsAlgorithmMismatch(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $token = $this->encoder->encode(['sub' => 'user'], $signer);

        $rsaKey = $this->generateRsaKey();
        $wrongVerifier = new Rs256Verifier(PublicKey::fromPrivateKey($rsaKey));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Algorithm mismatch');
        $this->decoder->decode($token->toString(), $wrongVerifier);
    }

    public function testVerifiedTokenHasClaim(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['sub' => 'alice', 'custom' => 'value'], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier);

        $this->assertTrue($verified->hasClaim('sub'));
        $this->assertTrue($verified->hasClaim('custom'));
        $this->assertFalse($verified->hasClaim('nonexistent'));
        $this->assertSame('value', $verified->getClaim('custom'));
        $this->assertSame('default', $verified->getClaim('missing', 'default'));
    }

    public function testDisableExpVerification(): void
    {
        $secret = 'a-sufficiently-long-secret-key!!';
        $signer = new Hs256Signer($secret);
        $verifier = new Hs256Verifier($secret);

        $token = $this->encoder->encode(['exp' => time() - 3600], $signer);
        $verified = $this->decoder->decode($token->toString(), $verifier, ['verify_exp' => false]);

        $this->assertInstanceOf(VerifiedToken::class, $verified);
    }

    private function generateRsaKey(): PrivateKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        return PrivateKey::fromString($pem);
    }

    private function generateEcKey(): PrivateKey
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_pkey_export($key, $pem);
        return PrivateKey::fromString($pem);
    }
}
