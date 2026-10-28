# widthx/auth

Framework-agnostic PHP client for [Widthx Identity](https://accounts.widthx.com) (OpenID Connect / OAuth 2.0):
Authorization Code + PKCE, ID token validation, refresh, RP-initiated logout, access-token and back-channel
logout-token verification (JWKS with caching and key rotation). PHP 8.2+.

For Laravel, use [`widthx/laravel-auth`](https://github.com/widthxhq/laravel-auth).

## Install

```bash
composer require widthx/auth
```

## Use

```php
use Widthx\Auth\AccessTokenVerifier;
use Widthx\Auth\Config;
use Widthx\Auth\PendingAuthorization;
use Widthx\Auth\Widthx;

$widthx = Widthx::create(new Config(
    issuer: 'https://accounts.widthx.com',
    clientId: 'your-app-production',
    clientSecret: getenv('WIDTHX_CLIENT_SECRET') ?: null,
    redirectUri: 'https://app.example.com/auth/callback',
    scopes: ['openid', 'email', 'profile', 'offline_access'],
), cache: $psr16Cache);

// 1. Start sign-in: keep the pending authorization in the server-side session, redirect to $url.
[$url, $pending] = $widthx->client()->createAuthorization('/dashboard');
$_SESSION['widthx_pending'] = $pending->toArray();

// 2. Callback: validates state, PKCE, nonce and the ID token. The pending authorization is
//    single use: remove it from the session *before* handling the callback, success or not.
$data = $_SESSION['widthx_pending'] ?? null;
unset($_SESSION['widthx_pending']);
$tokens = $widthx->client()->handleCallback($_GET, is_array($data) ? PendingAuthorization::fromArray($data) : null);
$subject = $tokens->subject();          // the stable user id; never match accounts by email

// Later: refresh tokens rotate, persist the new one. Passing the session's subject rejects
// a refreshed ID token issued for someone else.
$tokens = $widthx->client()->refresh($tokens->refreshToken, expectedSubject: $subject);

// 3. APIs: verify a Bearer access token.
$bearer = AccessTokenVerifier::bearer($_SERVER['HTTP_AUTHORIZATION'] ?? null);
$token = $widthx->accessTokens('my-api')->verify($bearer, requiredScopes: ['projects:read']);

// 4. Back-channel logout receiver: end the app sessions matching $claims['sid'] / $claims['sub'].
$claims = $widthx->logoutTokens()->verify($_POST['logout_token']);
```

Every failure is a `Widthx\Auth\Exception\WidthxAuthException`: `AuthorizationException` (login/token
endpoint, with an OAuth-style `$error` code), `InvalidTokenException` (HTTP 401) and
`InsufficientScopeException` (HTTP 403).

### Caching and the IdP

Pass a shared PSR-16 cache (Redis, APCu, …) in production. It holds the discovery document and the JWKS,
rate-limits JWKS refreshes triggered by unknown key ids (at most one per `jwksRefreshCooldownSeconds`,
default 60) and remembers back-channel logout `jti`s. Without a cache, every PHP request starts cold, and
**logout token replay is not detected**: store each returned `jti` for `maxAgeSeconds` (default 300) and
reject repeats yourself. Logout tokens older than `maxAgeSeconds` (by `iat`) are always rejected.

The default Guzzle client uses a 10 s timeout and 5 s connect timeout. If you pass your own client, set
timeouts on it: it is also used for the token endpoint.

## Testing your integration

`Widthx\Auth\Testing\FakeIdp` is an in-memory OpenID Provider (discovery, rotatable JWKS, scriptable
token endpoint) for your own test suite:

```php
$idp = new FakeIdp();
$widthx = Widthx::create(new Config(FakeIdp::ISSUER, 'client-a', 'secret', 'https://app.test/cb'), $idp->httpClient());
$idp->tokenResponses[] = [['access_token' => 'at', 'expires_in' => 900, 'id_token' => $idp->sign(FakeIdp::baseClaims('client-a', ['nonce' => $pending->nonce]))], 200];
$token = $idp->sign(FakeIdp::baseClaims('my-api', ['scp' => ['projects:read']]));
```

## Development

This package is developed in the Widthx monorepo and mirrored here. Tests: `composer install && vendor/bin/phpunit`.

## License

MIT
