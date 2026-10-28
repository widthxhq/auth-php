<?php

declare(strict_types=1);

namespace Widthx\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Entry point.
 *
 *   $widthx = Widthx::create(new Config(issuer: 'https://accounts.widthx.com', clientId: '…', clientSecret: '…', redirectUri: '…'));
 *   [$url, $pending] = $widthx->client()->createAuthorization('/dashboard');
 *   $tokens = $widthx->client()->handleCallback($_GET, $pending);
 *   $token  = $widthx->accessTokens('my-api')->verify(AccessTokenVerifier::bearer($header), ['projects:read']);
 */
final class Widthx
{
    private function __construct(
        private readonly Config $config,
        private readonly Http $http,
        private readonly Discovery $discovery,
        private readonly JwtVerifier $jwt,
        private readonly ?CacheInterface $cache,
    ) {
    }

    public static function create(Config $config, ?ClientInterface $httpClient = null, ?CacheInterface $cache = null): self
    {
        // Also used by league/oauth2-client for the token endpoint: never wait indefinitely.
        $http = new Http($httpClient ?? new Client(['timeout' => 10, 'connect_timeout' => 5]), $cache);
        $discovery = new Discovery($http, $config->issuer, $config->metadataTtlSeconds);
        $jwt = new JwtVerifier($http, $discovery, $config->issuer, $config->allowedAlgorithms, $config->clockSkewSeconds, $config->jwksTtlSeconds, $config->jwksRefreshCooldownSeconds);
        return new self($config, $http, $discovery, $jwt, $cache);
    }

    public function client(): OidcClient
    {
        return new OidcClient($this->config, $this->http, $this->discovery, $this->jwt);
    }

    public function accessTokens(string $audience): AccessTokenVerifier
    {
        return new AccessTokenVerifier($this->jwt, $audience);
    }

    /** With a PSR-16 cache configured, replayed logout tokens (same jti) are rejected. */
    public function logoutTokens(int $maxAgeSeconds = 300): LogoutTokenVerifier
    {
        return new LogoutTokenVerifier($this->jwt, $this->config->clientId, $maxAgeSeconds, $this->config->clockSkewSeconds, $this->cache);
    }

    public function config(): Config
    {
        return $this->config;
    }
}
