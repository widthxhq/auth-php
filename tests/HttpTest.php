<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Widthx\Auth\Exception\WidthxAuthException;
use Widthx\Auth\Http;

final class HttpTest extends TestCase
{
    /** @var list<array<string, mixed>> */
    private array $history = [];

    private function http(Response ...$responses): Http
    {
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($this->history));
        return new Http(new Client(['handler' => $stack]));
    }

    public function testFetchesJson(): void
    {
        self::assertSame(['a' => 1], $this->http(new Response(200, [], '{"a":1}'))->getJson('https://idp.test/x', 60));
    }

    public function testDoesNotFollowRedirectToPlainHttp(): void
    {
        $http = $this->http(new Response(302, ['Location' => 'http://evil.test/jwks']), new Response(200, [], '{"keys":[]}'));
        try {
            $http->getJson('https://idp.test/jwks', 60);
            self::fail('expected WidthxAuthException');
        } catch (WidthxAuthException) {
            self::assertCount(1, $this->history);
        }
    }

    public function testRejectsNon2xx(): void
    {
        $this->expectException(WidthxAuthException::class);
        $this->http(new Response(500, [], '{"a":1}'))->getJson('https://idp.test/x', 60);
    }

    public function testCapsResponseSize(): void
    {
        $this->expectException(WidthxAuthException::class);
        $this->http(new Response(200, [], '{"a":"' . str_repeat('x', 1024 * 1024) . '"}'))->getJson('https://idp.test/x', 60);
    }
}
