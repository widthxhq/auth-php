<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Widthx\Auth\AccessTokenVerifier;
use Widthx\Auth\Config;
use Widthx\Auth\Exception\InvalidTokenException;
use Widthx\Auth\Testing\FakeIdp;
use Widthx\Auth\Widthx;

final class JwksTest extends TestCase
{
    private FakeIdp $idp;

    protected function setUp(): void
    {
        $this->idp = new FakeIdp();
    }

    private function verifier(?ArrayCache $cache = null): AccessTokenVerifier
    {
        return Widthx::create(new Config(FakeIdp::ISSUER, 'client-a', 'secret', 'https://app.test/cb'), $this->idp->httpClient(), $cache)
            ->accessTokens('my-api');
    }

    private function forged(string $kid): string
    {
        $attacker = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        return $this->idp->sign(FakeIdp::baseClaims('my-api'), $kid, 'RS256', $attacker);
    }

    private static function rejects(callable $fn): void
    {
        try {
            $fn();
            self::fail('expected InvalidTokenException');
        } catch (InvalidTokenException) {
            self::assertTrue(true);
        }
    }

    public function testUnknownKidForcesAtMostOneRefreshPerWindow(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->idp->sign(FakeIdp::baseClaims('my-api')));
        for ($i = 0; $i < 5; $i++) {
            self::rejects(fn () => $verifier->verify($this->forged("unknown-{$i}")));
        }
        self::assertSame(2, $this->idp->requestCount('/jwks.json'), 'initial fetch + one forced refresh');
    }

    public function testRefreshWindowIsSharedThroughTheCache(): void
    {
        $cache = new ArrayCache();
        $this->verifier($cache)->verify($this->idp->sign(FakeIdp::baseClaims('my-api')));
        self::rejects(fn () => $this->verifier($cache)->verify($this->forged('unknown-1')));
        // a later request (fresh instance, same cache) must not refetch again
        self::rejects(fn () => $this->verifier($cache)->verify($this->forged('unknown-2')));
        self::assertSame(2, $this->idp->requestCount('/jwks.json'));
    }

    public function testKeyRotationStillRefreshes(): void
    {
        $cache = new ArrayCache();
        $this->verifier($cache)->verify($this->idp->sign(FakeIdp::baseClaims('my-api')));
        $this->idp->addKey('k2');
        $this->idp->activeKid = 'k2';
        self::assertSame('user-123', $this->verifier($cache)->verify($this->idp->sign(FakeIdp::baseClaims('my-api')))->subject);
    }

    /** @return iterable<string, array{0: ?string}> */
    public static function badKids(): iterable
    {
        yield 'missing' => [null];
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 300)];
        yield 'control chars' => ["k1\n"];
    }

    #[DataProvider('badKids')]
    public function testMalformedKidIsRejectedWithoutFetchingJwks(?string $kid): void
    {
        $b64 = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $header = ['alg' => 'RS256', 'typ' => 'JWT'] + ($kid === null ? [] : ['kid' => $kid]);
        $token = $b64(json_encode($header)) . '.' . $b64(json_encode(FakeIdp::baseClaims('my-api'))) . '.' . $b64('sig');
        self::rejects(fn () => $this->verifier()->verify($token));
        self::assertSame(0, $this->idp->requestCount('/jwks.json'));
    }

    public function testUnusableKeysAreSkipped(): void
    {
        $good = $this->idp->jwks()['keys'];
        $this->idp->jwksOverride = [
            ['kty' => 'RSA', 'kid' => 'broken', 'alg' => 'RS256'], // no n/e
            ['kty' => 'oct', 'kid' => 'sym', 'k' => 'c2VjcmV0'],
            ['kty' => 'XYZ', 'kid' => 'weird'],
            ['kid' => 'no-kty'],
            'not-an-object',
            ['kty' => 'RSA', 'kid' => 'enc', 'use' => 'enc', 'n' => $good[0]['n'], 'e' => $good[0]['e']],
            ...$good,
        ];
        self::assertSame('user-123', $this->verifier()->verify($this->idp->sign(FakeIdp::baseClaims('my-api')))->subject);
    }

    public function testEncryptionKeyIsNotUsedForSignatures(): void
    {
        $good = $this->idp->jwks()['keys'][0];
        $this->idp->jwksOverride = [['use' => 'enc'] + $good];
        self::rejects(fn () => $this->verifier()->verify($this->idp->sign(FakeIdp::baseClaims('my-api'))));
    }

    public function testNoUsableKeysIsRejected(): void
    {
        $this->idp->jwksOverride = [['kty' => 'RSA', 'kid' => 'k1', 'alg' => 'RS256']];
        self::rejects(fn () => $this->verifier()->verify($this->idp->sign(FakeIdp::baseClaims('my-api'))));
    }
}
