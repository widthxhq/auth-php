<?php

declare(strict_types=1);

namespace Widthx\Auth;

use Psr\SimpleCache\CacheInterface;
use Widthx\Auth\Exception\InvalidTokenException;

/**
 * OpenID Connect Back-Channel Logout 1.0: validates the `logout_token` the IdP POSTs to the
 * app when a user signs out centrally. On success, end the app sessions matching sid and/or sub.
 *
 * Hydra's logout tokens carry no `exp`, so freshness is bounded by `iat` + `$maxAgeSeconds`.
 * Replays inside that window are rejected when a PSR-16 cache is given (jti is remembered);
 * without one, the caller must store the returned jti for `$maxAgeSeconds` and reject repeats.
 */
final class LogoutTokenVerifier
{
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';
    private const TYPES = ['JWT', 'logout+jwt'];

    public function __construct(
        private readonly JwtVerifier $jwt,
        private readonly string $clientId,
        private readonly int $maxAgeSeconds = 300,
        private readonly int $clockSkewSeconds = 5,
        private readonly ?CacheInterface $replayCache = null,
    ) {
    }

    /** @return array{sub: ?string, sid: ?string, jti: string} */
    public function verify(string $logoutToken): array
    {
        $claims = $this->jwt->verify($logoutToken, $this->clientId, ['iat', 'jti', 'events'], self::TYPES);
        $events = $claims['events'];
        if (!is_array($events) || !is_array($events[self::EVENT] ?? null)) {
            throw new InvalidTokenException('not a back-channel logout token');
        }
        if (array_key_exists('nonce', $claims)) {
            throw new InvalidTokenException('logout token must not contain a nonce');
        }
        if (!is_int($claims['iat']) || $claims['iat'] < time() - $this->maxAgeSeconds - $this->clockSkewSeconds) {
            throw new InvalidTokenException('logout token is too old');
        }
        $sub = self::optionalString($claims, 'sub');
        $sid = self::optionalString($claims, 'sid');
        if ($sub === null && $sid === null) {
            throw new InvalidTokenException('logout token needs sub or sid');
        }
        $jti = $claims['jti'];
        if (!is_string($jti) || $jti === '') {
            throw new InvalidTokenException('logout token needs jti');
        }
        if ($this->replayCache !== null) {
            $key = 'widthx_auth_logout_jti_' . hash('sha256', $jti);
            if ($this->replayCache->has($key)) {
                throw new InvalidTokenException('logout token replayed');
            }
            $this->replayCache->set($key, true, $this->maxAgeSeconds + 2 * $this->clockSkewSeconds);
        }
        return ['sub' => $sub, 'sid' => $sid, 'jti' => $jti];
    }

    /** @param array<string, mixed> $claims */
    private static function optionalString(array $claims, string $name): ?string
    {
        if (!array_key_exists($name, $claims)) {
            return null;
        }
        if (!is_string($claims[$name]) || $claims[$name] === '') {
            throw new InvalidTokenException("logout token has an invalid {$name}");
        }
        return $claims[$name];
    }
}
