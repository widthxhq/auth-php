<?php

declare(strict_types=1);

namespace Widthx\Auth;

/**
 * Per-login transaction secrets. Store server-side (e.g. the session) for the duration of the
 * redirect and pass back to {@see OidcClient::handleCallback()}. Never expose to the browser.
 */
final readonly class PendingAuthorization
{
    public function __construct(
        public string $state,
        public string $nonce,
        public string $codeVerifier,
        public string $returnTo = '/',
        public int $createdAt = 0,
    ) {
    }

    /** @return array{state: string, nonce: string, code_verifier: string, return_to: string, created_at: int} */
    public function toArray(): array
    {
        return ['state' => $this->state, 'nonce' => $this->nonce, 'code_verifier' => $this->codeVerifier, 'return_to' => $this->returnTo, 'created_at' => $this->createdAt];
    }

    public function isComplete(): bool
    {
        return $this->state !== '' && $this->nonce !== '' && $this->codeVerifier !== '';
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        // Malformed values become empty/zero, which handleCallback() rejects as an expired login.
        $string = static fn (string $key, string $default = ''): string => is_string($data[$key] ?? null) ? $data[$key] : $default;
        return new self(
            $string('state'),
            $string('nonce'),
            $string('code_verifier'),
            $string('return_to', '/'),
            is_int($data['created_at'] ?? null) ? $data['created_at'] : 0,
        );
    }
}
