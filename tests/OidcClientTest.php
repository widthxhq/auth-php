<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Widthx\Auth\Config;
use Widthx\Auth\Exception\AuthorizationException;
use Widthx\Auth\OidcClient;
use Widthx\Auth\PendingAuthorization;
use Widthx\Auth\Testing\FakeIdp;
use Widthx\Auth\Widthx;

final class OidcClientTest extends TestCase
{
    private FakeIdp $idp;
    private Widthx $widthx;

    protected function setUp(): void
    {
        $this->idp = new FakeIdp();
        $this->widthx = Widthx::create(new Config(
            issuer: FakeIdp::ISSUER,
            clientId: 'client-a',
            clientSecret: 's3cr3t',
            redirectUri: 'https://app.test/auth/widthx/callback',
            scopes: ['openid', 'email', 'offline_access'],
            audience: ['my-api'],
            postLogoutRedirectUri: 'https://app.test/',
        ), $this->idp->httpClient());
    }

    /** @return array{0: array<string, string>, 1: PendingAuthorization} */
    private function authorize(array $extra = []): array
    {
        [$url, $pending] = $this->widthx->client()->createAuthorization('/dashboard', $extra);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        return [$q, $pending];
    }

    public function testAuthorizationUrlUsesPkceStateNonce(): void
    {
        [$q, $pending] = $this->authorize(['prompt' => 'login', 'redirect_uri' => 'https://evil.test']);
        self::assertSame('code', $q['response_type']);
        self::assertSame('S256', $q['code_challenge_method']);
        self::assertSame(rtrim(strtr(base64_encode(hash('sha256', $pending->codeVerifier, true)), '+/', '-_'), '='), $q['code_challenge']);
        self::assertSame($pending->state, $q['state']);
        self::assertSame($pending->nonce, $q['nonce']);
        self::assertSame('https://app.test/auth/widthx/callback', $q['redirect_uri'], 'extra params cannot override redirect_uri');
        self::assertSame('login', $q['prompt']);
        self::assertSame('my-api', $q['audience']);
        self::assertSame('/dashboard', $pending->returnTo);
    }

    private function queueTokens(PendingAuthorization $p, array $idClaims = []): void
    {
        $this->idp->tokenResponses[] = [[
            'access_token' => 'at', 'refresh_token' => 'rt', 'expires_in' => 900, 'token_type' => 'bearer',
            'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-a', $idClaims + ['nonce' => $p->nonce, 'email' => 'ada@example.com'])),
        ], 200];
    }

    public function testCallbackExchangesCodeAndValidatesIdToken(): void
    {
        [, $p] = $this->authorize();
        $this->queueTokens($p);
        $tokens = $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p);
        self::assertSame('user-123', $tokens->subject());
        self::assertSame('rt', $tokens->refreshToken);
        $token = array_values(array_filter($this->idp->history, fn ($h) => str_ends_with($h['request']->getUri()->getPath(), '/oauth2/token')));
        $req = $token[0]['request'];
        parse_str((string) $req->getBody(), $form);
        self::assertSame($p->codeVerifier, $form['code_verifier']);
        self::assertStringStartsWith('Basic ', $req->getHeaderLine('Authorization'));
    }

    public function testStateMismatchIsRejected(): void
    {
        [, $p] = $this->authorize();
        $this->assertAuthError('state_mismatch', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => 'forged'], $p));
    }

    public function testNonceMismatchIsRejected(): void
    {
        [, $p] = $this->authorize();
        $this->queueTokens($p, ['nonce' => 'other']);
        $this->expectException(AuthorizationException::class);
        $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p);
    }

    public function testIdTokenForAnotherClientIsRejected(): void
    {
        [, $p] = $this->authorize();
        $this->idp->tokenResponses[] = [['access_token' => 'at', 'expires_in' => 900, 'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-b', ['nonce' => $p->nonce]))], 200];
        $this->expectException(AuthorizationException::class);
        $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p);
    }

    public function testErrorResponseIsSurfaced(): void
    {
        [, $p] = $this->authorize();
        try {
            $this->widthx->client()->handleCallback(['error' => 'access_denied', 'state' => $p->state], $p);
            self::fail('expected exception');
        } catch (AuthorizationException $e) {
            self::assertSame('access_denied', $e->error);
        }
    }

    public function testMissingOrExpiredPendingAuthorization(): void
    {
        $this->assertAuthError('login_expired', fn () => $this->widthx->client()->handleCallback(['code' => 'x', 'state' => 'y'], null));
    }

    public function testEndSessionUrl(): void
    {
        $url = $this->widthx->client()->endSessionUrl('idt');
        self::assertStringStartsWith(FakeIdp::ISSUER . '/oauth2/sessions/logout?', $url);
        self::assertStringContainsString('post_logout_redirect_uri=https%3A%2F%2Fapp.test%2F', $url);
    }

    public function testSafeReturnTo(): void
    {
        self::assertSame('/x?y=1', OidcClient::safeReturnTo('/x?y=1'));
        foreach (['https://evil.test', '//evil.test', '/\\evil', "/a\nb", ''] as $bad) {
            self::assertSame('/', OidcClient::safeReturnTo($bad));
        }
    }

    private function assertAuthError(string $code, callable $fn): void
    {
        try {
            $fn();
            self::fail("expected {$code}");
        } catch (AuthorizationException $e) {
            self::assertSame($code, $e->error);
        }
    }

    public function testRejectsInsecureIssuer(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Config('http://auth.example.test', 'c', null, 'https://app.test/cb');
    }

    /** @return iterable<string, array{0: string}> */
    public static function insecureIssuers(): iterable
    {
        yield 'plain http' => ['http://auth.example.test'];
        yield 'http on a loopback-looking subdomain' => ['http://localhost.evil.test'];
    }

    #[DataProvider('insecureIssuers')]
    public function testRejectsInsecureIssuerVariants(string $issuer): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Config($issuer, 'c', null, 'https://app.test/cb');
    }

    public function testAcceptsLoopbackIssuers(): void
    {
        foreach (['http://localhost:4444', 'http://127.0.0.1:4444', 'http://[::1]:4444', 'http://[::1]'] as $issuer) {
            self::assertSame($issuer, (new Config($issuer, 'c', null, 'https://app.test/cb'))->issuer);
        }
    }

    /** @return iterable<string, array{0: list<string>}> */
    public static function weakAlgorithms(): iterable
    {
        yield 'HS256' => [['RS256', 'HS256']];
        yield 'hs512' => [['hs512']];
        yield 'none' => [['none']];
        yield 'empty' => [[]];
    }

    #[DataProvider('weakAlgorithms')]
    public function testRejectsSymmetricOrNoneAlgorithms(array $algorithms): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Config(FakeIdp::ISSUER, 'c', null, 'https://app.test/cb', allowedAlgorithms: $algorithms);
    }

    public function testTokenEndpointConnectFailureIsWrapped(): void
    {
        [, $p] = $this->authorize();
        $this->idp->tokenResponses[] = new ConnectException('connection refused', new Request('POST', FakeIdp::ISSUER . '/oauth2/token'));
        $this->assertAuthError('token_error', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p));
    }

    public function testMultipleAudiencesRequireAzp(): void
    {
        [, $p] = $this->authorize();
        $this->queueTokens($p, ['aud' => ['client-a', 'other']]);
        $this->assertAuthError('invalid_id_token', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p));

        [, $p] = $this->authorize();
        $this->queueTokens($p, ['aud' => ['client-a', 'other'], 'azp' => 'other']);
        $this->assertAuthError('invalid_id_token', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p));

        [, $p] = $this->authorize();
        $this->queueTokens($p, ['aud' => ['client-a', 'other'], 'azp' => 'client-a']);
        self::assertSame('user-123', $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p)->subject());
    }

    public function testRefreshedIdTokenMustKeepTheSubject(): void
    {
        $this->idp->tokenResponses[] = [['access_token' => 'at2', 'refresh_token' => 'rt2', 'expires_in' => 900, 'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-a', ['sub' => 'someone-else']))], 200];
        $this->assertAuthError('invalid_id_token', fn () => $this->widthx->client()->refresh('rt', expectedSubject: 'user-123'));

        $this->idp->tokenResponses[] = [['access_token' => 'at2', 'refresh_token' => 'rt2', 'expires_in' => 900, 'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-a'))], 200];
        self::assertSame('rt2', $this->widthx->client()->refresh('rt', expectedSubject: 'user-123')->refreshToken);
    }

    public function testIdTokenMustNotBeAnotherTokenKind(): void
    {
        [, $p] = $this->authorize();
        $this->idp->tokenResponses[] = [['access_token' => 'at', 'expires_in' => 900, 'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-a', ['nonce' => $p->nonce]), header: ['typ' => 'at+jwt'])], 200];
        $this->assertAuthError('invalid_id_token', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p));
    }

    /** @return iterable<string, array{0: array<string, mixed>}> */
    public static function incompletePending(): iterable
    {
        yield 'empty state' => [['state' => '']];
        yield 'empty nonce' => [['nonce' => '']];
        yield 'empty code_verifier' => [['code_verifier' => '']];
        yield 'non-string state' => [['state' => ['x']]];
    }

    #[DataProvider('incompletePending')]
    public function testIncompletePendingAuthorizationIsRejected(array $override): void
    {
        $data = $override + ['state' => 'st', 'nonce' => 'n', 'code_verifier' => str_repeat('v', 43), 'return_to' => '/', 'created_at' => time()];
        $pending = PendingAuthorization::fromArray($data);
        // An empty stored state would otherwise match a callback without state (and an empty nonce an ID token without one).
        $this->idp->tokenResponses[] = [['access_token' => 'at', 'expires_in' => 900, 'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-a'))], 200];
        $this->assertAuthError('login_expired', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => is_string($data['state']) ? $data['state'] : ''], $pending));
    }

    public function testNonStringQueryValuesAreTreatedAsMissing(): void
    {
        [, $p] = $this->authorize();
        $this->assertAuthError('state_mismatch', fn () => $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => [$p->state]], $p));
        $this->assertAuthError('invalid_request', fn () => $this->widthx->client()->handleCallback(['code' => ['abc'], 'state' => $p->state], $p));
        // a non-string error is ignored rather than cast to "Array"
        $this->assertAuthError('invalid_request', fn () => $this->widthx->client()->handleCallback(['error' => ['x'], 'state' => $p->state], $p));
    }

    public function testExpiresAtIsNullWithoutExpiresIn(): void
    {
        [, $p] = $this->authorize();
        $this->idp->tokenResponses[] = [['access_token' => 'at', 'id_token' => $this->idp->sign(FakeIdp::baseClaims('client-a', ['nonce' => $p->nonce]))], 200];
        $tokens = $this->widthx->client()->handleCallback(['code' => 'abc', 'state' => $p->state], $p);
        self::assertNull($tokens->expiresAt);
        self::assertFalse($tokens->isExpired());
    }
}
