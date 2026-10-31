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

    /**
     * The account's roles on a site (Widthx site memberships), or [] when the token was issued for another site
     * (or none). Never trust `roles` without checking `site`: a token for another site carries other roles.
     *
     * @return list<string>
     */
    public function rolesFor(string $site): array
    {
        if (($this->claims['site'] ?? null) !== $site || !is_array($this->claims['roles'] ?? null)) {
            return [];
        }
        return array_values(array_filter($this->claims['roles'], 'is_string'));
    }
}
