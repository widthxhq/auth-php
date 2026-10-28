<?php

declare(strict_types=1);

namespace Widthx\Auth\Exception;

/** The token is valid but lacks a scope required by the endpoint (HTTP 403). */
final class InsufficientScopeException extends WidthxAuthException
{
    /** @param list<string> $missing */
    public function __construct(public readonly array $missing)
    {
        parent::__construct('missing scope: ' . implode(' ', $missing));
    }
}
