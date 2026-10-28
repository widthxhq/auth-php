<?php

declare(strict_types=1);

namespace Widthx\Auth\Exception;

/**
 * The authorization response or token exchange failed: OAuth error returned by the IdP
 * (e.g. access_denied), state mismatch, or an invalid ID token.
 */
final class AuthorizationException extends WidthxAuthException
{
    public function __construct(public readonly string $error, string $message = '', ?\Throwable $previous = null)
    {
        parent::__construct($message !== '' ? $message : $error, 0, $previous);
    }
}
