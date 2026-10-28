<?php

declare(strict_types=1);

namespace Widthx\Auth\Exception;

/** The token is missing, malformed, expired, wrongly signed or issued for someone else (HTTP 401). */
final class InvalidTokenException extends WidthxAuthException
{
}
