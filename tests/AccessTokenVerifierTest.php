<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Widthx\Auth\AccessTokenVerifier;
use Widthx\Auth\Config;
use Widthx\Auth\Exception\InsufficientScopeException;
use Widthx\Auth\Exception\InvalidTokenException;
use Widthx\Auth\Testing\FakeIdp;
use Widthx\Auth\Widthx;

final class AccessTokenVerifierTest extends TestCase
{
    private FakeIdp $idp;
    private AccessTokenVerifier $verifier;

    protected function setUp(): void
    {
        $this->idp = new FakeIdp();
        $widthx = Widthx::create(new Config(FakeIdp::ISSUER, 'client-a', 'secret', 'https://app.test/cb'), $this->idp->httpClient());
        $this->verifier = $widthx->accessTokens('my-api');
    }

    private function token(array $extra = []): string
    {
        return $this->idp->sign(FakeIdp::baseClaims('my-api', $extra + ['scp' => ['openid', 'projects:read'], 'client_id' => 'client-a']));
    }

    public function testAcceptsValidToken(): void
    {
        $t = $this->verifier->verify($this->token(), ['projects:read']);
        self::assertSame('user-123', $t->subject);
        self::assertSame('client-a', $t->clientId);
        self::assertTrue($t->hasScope('openid'));
    }

    public static function invalidClaims(): iterable
    {
        yield 'wrong issuer' => [['iss' => 'https://evil.test']];
        yield 'wrong audience' => [['aud' => ['other-api']]];
        yield 'expired' => [['exp' => time() - 60, 'iat' => time() - 600]];
        yield 'not yet valid' => [['nbf' => time() + 600]];
    }

    #[DataProvider('invalidClaims')]
    public function testRejectsInvalidClaims(array $override): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($this->token($override));
    }

    public function testRejectsUnknownSigningKey(): void
    {
        $attacker = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $forged = $this->idp->sign(FakeIdp::baseClaims('my-api'), 'k1', 'RS256', $attacker);
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($forged);
    }

    public function testRejectsAlgNone(): void
    {
        $b64 = fn (array $a) => rtrim(strtr(base64_encode(json_encode($a)), '+/', '-_'), '=');
        $unsigned = $b64(['alg' => 'none', 'typ' => 'JWT']) . '.' . $b64(FakeIdp::baseClaims('my-api')) . '.';
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($unsigned);
    }

    public function testRejectsHs256KeyConfusion(): void
    {
        $b64 = fn (string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $h = $b64(json_encode(['alg' => 'HS256', 'kid' => 'k1'])) . '.' . $b64(json_encode(FakeIdp::baseClaims('my-api')));
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($h . '.' . $b64(hash_hmac('sha256', $h, 'guess', true)));
    }

    public function testRejectsTamperedPayload(): void
    {
        [$h, , $s] = explode('.', $this->token());
        $p = rtrim(strtr(base64_encode(json_encode(FakeIdp::baseClaims('my-api', ['sub' => 'admin']))), '+/', '-_'), '=');
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify("$h.$p.$s");
    }

    public function testFollowsKeyRotation(): void
    {
        $this->verifier->verify($this->token()); // caches JWKS with k1
        $this->idp->addKey('k2');
        $this->idp->activeKid = 'k2';
        self::assertSame('user-123', $this->verifier->verify($this->token())->subject);
    }

    public function testInsufficientScope(): void
    {
        $this->expectException(InsufficientScopeException::class);
        $this->verifier->verify($this->token(), ['projects:write']);
    }

    public function testBearerParsing(): void
    {
        self::assertSame('abc.def.ghi', AccessTokenVerifier::bearer('Bearer abc.def.ghi'));
        self::assertSame('abc.def.ghi', AccessTokenVerifier::bearer('bearer abc.def.ghi'), 'auth scheme is case-insensitive');
        self::assertSame('abc.def.ghi', AccessTokenVerifier::bearer('BEARER abc.def.ghi'));
        foreach (['Basic abc', "Bearer abc.def.ghi\n", 'Bearer ', '', null] as $bad) {
            try {
                AccessTokenVerifier::bearer($bad);
                self::fail('accepted ' . var_export($bad, true));
            } catch (InvalidTokenException) {
                self::assertTrue(true);
            }
        }
    }

    public function testIdTokenForTheApiAudienceIsRejected(): void
    {
        // An ID token whose aud happens to equal the API audience must not pass as an access token.
        $idToken = $this->idp->sign(FakeIdp::baseClaims('my-api', ['nonce' => 'n', 'at_hash' => 'h', 'scp' => ['projects:read']]));
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($idToken);
    }

    /** @return iterable<string, array{0: array<string, mixed>}> */
    public static function nonAccessTokenClaims(): iterable
    {
        yield 'nonce (ID token)' => [['nonce' => 'n']];
        yield 'at_hash (ID token)' => [['at_hash' => 'h']];
        yield 'events (logout token)' => [['events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()]]];
    }

    #[DataProvider('nonAccessTokenClaims')]
    public function testRejectsOtherTokenKindsByClaims(array $extra): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier->verify($this->token($extra));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function headerTypes(): iterable
    {
        yield 'JWT (Hydra default)' => ['JWT', true];
        yield 'at+jwt' => ['at+jwt', true];
        yield 'application/at+jwt' => ['application/at+jwt', true];
        yield 'AT+JWT' => ['AT+JWT', true];
        yield 'logout+jwt' => ['logout+jwt', false];
        yield 'id_token+jwt' => ['id_token+jwt', false];
        yield 'JOSE+JSON' => ['JOSE+JSON', false];
    }

    #[DataProvider('headerTypes')]
    public function testHeaderType(string $typ, bool $accepted): void
    {
        $token = $this->idp->sign(FakeIdp::baseClaims('my-api', ['scp' => ['projects:read']]), header: ['typ' => $typ]);
        if (!$accepted) {
            $this->expectException(InvalidTokenException::class);
        }
        self::assertSame('user-123', $this->verifier->verify($token)->subject);
    }
}
