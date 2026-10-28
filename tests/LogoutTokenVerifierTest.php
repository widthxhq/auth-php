<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Widthx\Auth\Config;
use Widthx\Auth\Exception\InvalidTokenException;
use Widthx\Auth\LogoutTokenVerifier;
use Widthx\Auth\Testing\FakeIdp;
use Widthx\Auth\Widthx;

final class LogoutTokenVerifierTest extends TestCase
{
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private FakeIdp $idp;
    private LogoutTokenVerifier $verifier;

    protected function setUp(): void
    {
        $this->idp = new FakeIdp();
        $this->verifier = $this->widthx()->logoutTokens();
    }

    private function widthx(?ArrayCache $cache = null): Widthx
    {
        return Widthx::create(new Config(FakeIdp::ISSUER, 'client-a', 'secret', 'https://app.test/cb'), $this->idp->httpClient(), $cache);
    }

    /**
     * Shaped like Hydra's logout token: iss, aud, iat, jti, events, sid and no exp or sub.
     *
     * @param array<string, mixed> $override
     * @param list<string> $remove
     * @param array<string, mixed> $header
     */
    private function token(array $override = [], array $remove = [], array $header = []): string
    {
        $claims = $override + ['iss' => FakeIdp::ISSUER, 'aud' => ['client-a'], 'iat' => time(), 'jti' => bin2hex(random_bytes(8)), 'events' => [self::EVENT => new \stdClass()], 'sid' => 's1'];
        foreach ($remove as $name) {
            unset($claims[$name]);
        }
        return $this->idp->sign($claims, header: $header);
    }

    public function testAcceptsHydraShapedToken(): void
    {
        self::assertSame(['sub' => null, 'sid' => 's1', 'jti' => 'j1'], $this->verifier->verify($this->token(['jti' => 'j1'])));
        $withSub = $this->verifier->verify($this->token(['sub' => 'user-123', 'exp' => time() + 120], ['sid']));
        self::assertSame('user-123', $withSub['sub']);
        self::assertNull($withSub['sid']);
    }

    /** @return iterable<string, array{0: array<string, mixed>, 1: list<string>}> */
    public static function invalid(): iterable
    {
        yield 'no iat' => [[], ['iat']];
        yield 'no jti' => [[], ['jti']];
        yield 'empty jti' => [['jti' => ''], []];
        yield 'no events' => [[], ['events']];
        yield 'wrong event' => [['events' => ['http://schemas.openid.net/event/other' => new \stdClass()]], []];
        yield 'event not an object' => [['events' => [self::EVENT => 'yes']], []];
        yield 'nonce present' => [['nonce' => 'n'], []];
        yield 'neither sub nor sid' => [[], ['sid']];
        yield 'non-string sid' => [['sid' => ['s1']], []];
        yield 'expired' => [['exp' => time() - 60], []];
        yield 'issued too long ago' => [['iat' => time() - 3600], []];
        yield 'wrong audience' => [['aud' => ['client-b']], []];
    }

    #[DataProvider('invalid')]
    public function testRejects(array $override, array $remove): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($this->token($override, $remove));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function headerTypes(): iterable
    {
        yield 'JWT (Hydra default)' => ['JWT', true];
        yield 'logout+jwt' => ['logout+jwt', true];
        yield 'application/logout+jwt' => ['application/logout+jwt', true];
        yield 'at+jwt' => ['at+jwt', false];
        yield 'secevent+jwt' => ['secevent+jwt', false];
    }

    #[DataProvider('headerTypes')]
    public function testHeaderType(string $typ, bool $accepted): void
    {
        if (!$accepted) {
            $this->expectException(InvalidTokenException::class);
        }
        self::assertSame('s1', $this->verifier->verify($this->token(header: ['typ' => $typ]))['sid']);
    }

    public function testMaxAgeIsConfigurable(): void
    {
        $verifier = $this->widthx()->logoutTokens(maxAgeSeconds: 30);
        $this->expectException(InvalidTokenException::class);
        $verifier->verify($this->token(['iat' => time() - 60]));
    }

    public function testReplayIsRejectedWhenACacheIsConfigured(): void
    {
        $cache = new ArrayCache();
        $token = $this->token();
        self::assertSame('s1', $this->widthx($cache)->logoutTokens()->verify($token)['sid']);
        $this->expectException(InvalidTokenException::class);
        $this->widthx($cache)->logoutTokens()->verify($token);
    }
}
