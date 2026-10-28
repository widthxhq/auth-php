<?php

declare(strict_types=1);

namespace Widthx\Auth\Testing;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * In-memory OpenID Provider for tests: discovery, JWKS (rotatable keys) and a scriptable token
 * endpoint. Pass {@see httpClient()} to {@see \Widthx\Auth\Widthx::create()} and sign tokens with
 * {@see sign()}. Not for production use.
 */
final class FakeIdp
{
    public const ISSUER = 'https://auth.example.test';

    /** @var array<string, \OpenSSLAsymmetricKey> */
    private array $keys = [];
    public string $activeKid = 'k1';
    /**
     * Queued token endpoint responses, consumed in order: [body, status] or a Throwable to fail the
     * request (e.g. a GuzzleHttp\Exception\ConnectException). An empty queue answers invalid_grant.
     *
     * @var list<array{0: array<string, mixed>, 1: int}|\Throwable>
     */
    public array $tokenResponses = [];
    /** @var list<array{request: RequestInterface}> */
    public array $history = [];
    /** @var list<array<string, mixed>>|null when set, published as the JWKS `keys` instead of the signing keys */
    public ?array $jwksOverride = null;

    public function __construct()
    {
        $this->addKey('k1');
    }

    public function addKey(string $kid): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw new \RuntimeException('openssl_pkey_new failed');
        }
        return $this->keys[$kid] = $key;
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header extra JOSE header parameters, e.g. ['typ' => 'at+jwt']
     */
    public function sign(array $claims, ?string $kid = null, string $alg = 'RS256', ?\OpenSSLAsymmetricKey $key = null, array $header = []): string
    {
        $kid ??= $this->activeKid;
        return JWT::encode($claims, $key ?? $this->keys[$kid], $alg, $kid, $header === [] ? null : $header);
    }

    /** @return array{keys: list<array<string, mixed>>} */
    public function jwks(): array
    {
        if ($this->jwksOverride !== null) {
            return ['keys' => $this->jwksOverride];
        }
        $keys = [];
        foreach ($this->keys as $kid => $key) {
            $d = openssl_pkey_get_details($key)['rsa'];
            $keys[] = ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => JWT::urlsafeB64Encode($d['n']), 'e' => JWT::urlsafeB64Encode($d['e'])];
        }
        return ['keys' => $keys];
    }

    /** Number of requests made so far whose path ends with $pathSuffix (e.g. '/jwks.json'). */
    public function requestCount(string $pathSuffix): int
    {
        return count(array_filter($this->history, static fn (array $h): bool => str_ends_with($h['request']->getUri()->getPath(), $pathSuffix)));
    }

    public function httpClient(): Client
    {
        $stack = HandlerStack::create(fn (RequestInterface $request): PromiseInterface => $this->respond($request));
        $stack->push(Middleware::history($this->history));
        return new Client(['handler' => $stack]);
    }

    private function respond(RequestInterface $request): PromiseInterface
    {
        $path = $request->getUri()->getPath();
        if (str_ends_with($path, '/oauth2/token')) {
            $next = array_shift($this->tokenResponses) ?? [['error' => 'invalid_grant'], 400];
            return $next instanceof \Throwable ? Create::rejectionFor($next) : Create::promiseFor(self::json(...$next));
        }
        return Create::promiseFor(match (true) {
            str_ends_with($path, '/.well-known/openid-configuration') => self::json([
                'issuer' => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/oauth2/auth',
                'token_endpoint' => self::ISSUER . '/oauth2/token',
                'jwks_uri' => self::ISSUER . '/.well-known/jwks.json',
                'end_session_endpoint' => self::ISSUER . '/oauth2/sessions/logout',
                'userinfo_endpoint' => self::ISSUER . '/userinfo',
            ]),
            str_ends_with($path, '/.well-known/jwks.json') => self::json($this->jwks()),
            default => new Response(404),
        });
    }

    /** @param array<string, mixed> $body */
    private static function json(array $body, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
    }

    /**
     * Registered claims for a token issued by this IdP to $aud, valid for five minutes.
     *
     * @param array<string, mixed> $extra overrides and additional claims
     * @return array<string, mixed>
     */
    public static function baseClaims(string $aud, array $extra = []): array
    {
        $now = time();
        return $extra + ['iss' => self::ISSUER, 'sub' => 'user-123', 'aud' => [$aud], 'iat' => $now, 'exp' => $now + 300];
    }
}
