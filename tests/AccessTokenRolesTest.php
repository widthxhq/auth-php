<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Widthx\Auth\AccessToken;

final class AccessTokenRolesTest extends TestCase
{
    private static function token(array $claims): AccessToken
    {
        return new AccessToken('sub-1', 'client-a', [], time() + 60, $claims);
    }

    public function testRolesOfTheTokensSite(): void
    {
        self::assertSame(['admin', 'editor'], self::token(['site' => 'pharmed-admin', 'roles' => ['admin', 'editor']])->rolesFor('pharmed-admin'));
    }

    public function testNoRolesFromATokenForAnotherSiteOrWithoutSite(): void
    {
        self::assertSame([], self::token(['site' => 'other', 'roles' => ['admin']])->rolesFor('pharmed-admin'));
        self::assertSame([], self::token(['roles' => ['admin']])->rolesFor('pharmed-admin'));
        self::assertSame([], self::token(['site' => 'pharmed-admin', 'roles' => 'admin'])->rolesFor('pharmed-admin'));
    }
}
