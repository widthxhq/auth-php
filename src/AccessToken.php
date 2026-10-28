<?php

declare(strict_types=1);

namespace Widthx\Auth;

/** A verified access token. `subject` is the stable Widthx identity id: key your records on it. */
final readonly class AccessToken
{
    /**
     * @param list<string> $scopes
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public string $subject,
        public ?string $clientId,
        public array $scopes,
        public int $expiresAt,
        public array $claims,
    ) {
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
