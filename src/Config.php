<?php

declare(strict_types=1);

namespace Widthx\Auth;

/** Static configuration of one OIDC client registration (one app, one environment). */
final readonly class Config
{
    /**
     * @param list<string> $scopes
     * @param list<string> $audience API audiences to request access tokens for
     * @param list<string> $allowedAlgorithms
     */
    public function __construct(
        public string $issuer,
        public string $clientId,
        public ?string $clientSecret,
        public string $redirectUri,
        public array $scopes = ['openid', 'profile', 'email'],
        public array $audience = [],
        public ?string $postLogoutRedirectUri = null,
        public array $allowedAlgorithms = ['RS256', 'ES256'],
        public int $clockSkewSeconds = 5,
        public int $metadataTtlSeconds = 3600,
        public int $jwksTtlSeconds = 600,
        public int $jwksRefreshCooldownSeconds = 60,
    ) {
        if ($issuer === '' || $clientId === '' || $redirectUri === '') {
            throw new \InvalidArgumentException('issuer, clientId and redirectUri are required');
        }
        if (!str_starts_with($issuer, 'https://') && !self::isLoopback($issuer)) {
            throw new \InvalidArgumentException('issuer must use https (plain http is only allowed for localhost)');
        }
        if (!in_array('openid', $scopes, true)) {
            throw new \InvalidArgumentException('scopes must include openid');
        }
        if ($allowedAlgorithms === []) {
            throw new \InvalidArgumentException('allowedAlgorithms must not be empty');
        }
        foreach ($allowedAlgorithms as $alg) {
            // Tokens are verified against the issuer's public JWKS; a symmetric alg would turn a public key into an HMAC secret.
            if (!is_string($alg) || strcasecmp($alg, 'none') === 0 || stripos($alg, 'HS') === 0) {
                throw new \InvalidArgumentException('allowedAlgorithms must only contain asymmetric algorithms');
            }
        }
    }

    public static function isLoopback(string $url): bool
    {
        $host = parse_url($url, PHP_URL_HOST);
        return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }
}
