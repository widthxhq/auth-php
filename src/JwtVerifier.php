<?php

declare(strict_types=1);

namespace Widthx\Auth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Widthx\Auth\Exception\InvalidTokenException;

/**
 * Verifies JWS signatures against the issuer's JWKS (never hard-coded keys) and the registered
 * claims common to every Widthx token: exact issuer, audience, exp/nbf/iat with small skew,
 * and an algorithm allow-list. An unknown key id triggers a JWKS refresh (key rotation), at most
 * once per refresh window so forged kids cannot turn every request into an IdP round-trip.
 */
final class JwtVerifier
{
    private const KEY_TYPES = ['RSA', 'EC', 'OKP'];

    /** @param list<string> $allowedAlgorithms */
    public function __construct(
        private readonly Http $http,
        private readonly Discovery $discovery,
        private readonly string $issuer,
        private readonly array $allowedAlgorithms,
        private readonly int $clockSkew,
        private readonly int $jwksTtl,
        private readonly int $jwksRefreshCooldown = 60,
    ) {
    }

    /**
     * @param list<string> $requiredClaims claims that must be present (exp/nbf are always checked when present)
     * @param list<string> $acceptedTypes when non-empty, a `typ` header (if present) must be one of these,
     *                                    compared case-insensitively and without an `application/` prefix
     * @return array<string, mixed>
     */
    public function verify(string $jwt, string $audience, array $requiredClaims = ['sub', 'exp', 'iat'], array $acceptedTypes = []): array
    {
        $header = $this->header($jwt);
        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !in_array($alg, $this->allowedAlgorithms, true)) {
            throw new InvalidTokenException('algorithm not allowed');
        }
        if ($acceptedTypes !== [] && array_key_exists('typ', $header)) {
            $typ = is_string($header['typ']) ? self::mediaType($header['typ']) : null;
            if (!in_array($typ, array_map(self::mediaType(...), $acceptedTypes), true)) {
                throw new InvalidTokenException('unexpected token type');
            }
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || !preg_match('/^[\x21-\x7e]{1,128}$/D', $kid)) {
            throw new InvalidTokenException('missing or malformed key id');
        }
        $keys = $this->keys(false, $alg);
        if (!isset($keys[$kid])) {
            $keys = $this->keys(true, $alg); // rotated key: refresh (rate-limited in Http::getJson)
        }

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->clockSkew;
        try {
            $claims = json_decode(json_encode(JWT::decode($jwt, $keys), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw new InvalidTokenException('invalid token: ' . $e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new InvalidTokenException('issuer mismatch');
        }
        $aud = $claims['aud'] ?? [];
        $aud = is_array($aud) ? $aud : [$aud];
        if (!in_array($audience, $aud, true)) {
            throw new InvalidTokenException('audience mismatch');
        }
        foreach ($requiredClaims as $required) {
            if (!isset($claims[$required])) {
                throw new InvalidTokenException("missing claim {$required}");
            }
        }
        return $claims;
    }

    /** @return array<string, mixed> */
    private function header(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('malformed token');
        }
        $json = JWT::urlsafeB64Decode($parts[0]);
        $header = json_decode($json, true);
        if (!is_array($header)) {
            throw new InvalidTokenException('malformed token header');
        }
        return $header;
    }

    private static function mediaType(string $typ): string
    {
        $typ = strtolower($typ);
        return str_starts_with($typ, 'application/') ? substr($typ, 12) : $typ;
    }

    /**
     * Signature keys with a kid that php-jwt can parse; anything else in the set is skipped so one
     * odd key (encryption, unknown kty, bad encoding) does not take down verification.
     *
     * @return array<string, \Firebase\JWT\Key>
     */
    private function keys(bool $refresh, string $alg): array
    {
        $jwks = $this->http->getJson($this->discovery->endpoint('jwks_uri'), $this->jwksTtl, $refresh, $this->jwksRefreshCooldown);
        $keys = [];
        foreach (is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [] as $jwk) {
            if (!is_array($jwk) || !is_string($jwk['kid'] ?? null) || ($jwk['use'] ?? 'sig') !== 'sig'
                || !in_array($jwk['kty'] ?? null, self::KEY_TYPES, true)
                || (isset($jwk['alg']) && !in_array($jwk['alg'], $this->allowedAlgorithms, true))) {
                continue;
            }
            try {
                // A key without its own alg is bound to the (already allow-listed) token alg.
                $key = JWK::parseKey($jwk, $alg);
            } catch (\Throwable) {
                continue;
            }
            if ($key !== null) {
                $keys[$jwk['kid']] = $key;
            }
        }
        if ($keys === []) {
            throw new InvalidTokenException('JWKS has no usable signature keys');
        }
        return $keys;
    }
}
