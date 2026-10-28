<?php

declare(strict_types=1);

namespace Widthx\Auth;

/**
 * Tokens from the token endpoint. `idTokenClaims` are already validated when present.
 * `expiresAt` is null when the IdP did not say how long the access token lives.
 */
final readonly class TokenSet
{
    /** @param array<string, mixed> $idTokenClaims */
    public function __construct(
        public string $accessToken,
        public ?string $idToken,
        public ?string $refreshToken,
        public ?int $expiresAt,
        public array $idTokenClaims,
    ) {
    }

    public function subject(): ?string
    {
        return isset($this->idTokenClaims['sub']) ? (string) $this->idTokenClaims['sub'] : null;
    }

    public function isExpired(int $skew = 30): bool
    {
        return $this->expiresAt !== null && time() >= $this->expiresAt - $skew;
    }
}
