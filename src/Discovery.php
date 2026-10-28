<?php

declare(strict_types=1);

namespace Widthx\Auth;

use Widthx\Auth\Exception\WidthxAuthException;

/** OpenID Provider metadata (`/.well-known/openid-configuration`), with exact issuer matching. */
final class Discovery
{
    public function __construct(
        private readonly Http $http,
        private readonly string $issuer,
        private readonly int $ttl,
    ) {
    }

    /** @return array<string, mixed> */
    public function metadata(): array
    {
        $meta = $this->http->getJson(rtrim($this->issuer, '/') . '/.well-known/openid-configuration', $this->ttl);
        if (($meta['issuer'] ?? null) !== $this->issuer) {
            throw new WidthxAuthException('discovery issuer mismatch');
        }
        return $meta;
    }

    public function endpoint(string $name): string
    {
        $value = $this->metadata()[$name] ?? null;
        if (!is_string($value) || $value === '') {
            throw new WidthxAuthException("discovery document has no {$name}");
        }
        return $value;
    }
}
