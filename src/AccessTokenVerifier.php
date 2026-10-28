<?php

declare(strict_types=1);

namespace Widthx\Auth;

use Widthx\Auth\Exception\InsufficientScopeException;
use Widthx\Auth\Exception\InvalidTokenException;

/** Resource-server side: validates Widthx JWT access tokens for one API audience. */
final class AccessTokenVerifier
{
    /** Hydra signs JWT access tokens with `typ: JWT` (fosite default) or `at+jwt` (RFC 9068). */
    private const TYPES = ['JWT', 'at+jwt'];
    /** Claims that only ID tokens (nonce, at_hash) or logout tokens (events) carry. */
    private const FOREIGN_CLAIMS = ['nonce', 'at_hash', 'c_hash', 'events'];

    public function __construct(private readonly JwtVerifier $jwt, private readonly string $audience)
    {
    }

    /** Extracts the bearer token from an Authorization header value. */
    public static function bearer(?string $authorizationHeader): string
    {
        if ($authorizationHeader === null || !preg_match('/^Bearer +([A-Za-z0-9._~+\/-]+=*)$/iD', $authorizationHeader, $m)) {
            throw new InvalidTokenException('missing bearer token');
        }
        return $m[1];
    }

    /** @param list<string> $requiredScopes */
    public function verify(string $token, array $requiredScopes = []): AccessToken
    {
        $claims = $this->jwt->verify($token, $this->audience, acceptedTypes: self::TYPES);
        foreach (self::FOREIGN_CLAIMS as $claim) {
            if (array_key_exists($claim, $claims)) {
                throw new InvalidTokenException('not an access token');
            }
        }
        $scopes = $claims['scp'] ?? (isset($claims['scope']) ? explode(' ', (string) $claims['scope']) : []);
        $scopes = array_values(array_filter(array_map('strval', (array) $scopes)));
        $missing = array_values(array_diff($requiredScopes, $scopes));
        if ($missing !== []) {
            throw new InsufficientScopeException($missing);
        }
        return new AccessToken(
            subject: (string) $claims['sub'],
            clientId: isset($claims['client_id']) ? (string) $claims['client_id'] : null,
            scopes: $scopes,
            expiresAt: (int) $claims['exp'],
            claims: $claims,
        );
    }
}
