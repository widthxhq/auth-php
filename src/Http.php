<?php

declare(strict_types=1);

namespace Widthx\Auth;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\SimpleCache\CacheInterface;
use Widthx\Auth\Exception\WidthxAuthException;

/** Small JSON HTTP + cache helper shared by discovery and JWKS. */
final class Http
{
    /** Discovery documents and key sets are small; anything bigger is refused. */
    public const MAX_BODY_BYTES = 1048576;

    /** @var array<string, array{0: int, 1: mixed}> */
    private array $memory = [];

    public function __construct(
        private readonly ClientInterface $client,
        private readonly ?CacheInterface $cache = null,
    ) {
    }

    public function client(): ClientInterface
    {
        return $this->client;
    }

    /**
     * Fetches and caches a JSON document. `$refresh` bypasses the cache, but at most once per
     * `$refreshCooldown` seconds per URL (tracked in memory and in the PSR-16 cache), so callers
     * cannot be used to hammer the IdP; within the cooldown the cached document is returned.
     *
     * @return array<string, mixed>
     */
    public function getJson(string $url, int $ttl, bool $refresh = false, int $refreshCooldown = 60): array
    {
        $key = 'widthx_auth_' . hash('sha256', $url);
        if ($refresh && $this->remember($key . '_refreshed', $refreshCooldown) !== null) {
            $refresh = false;
        }
        if (!$refresh) {
            $cached = $this->remember($key, $ttl);
            if (is_array($cached)) {
                return $cached;
            }
        } else {
            $this->store($key . '_refreshed', true, $refreshCooldown);
        }
        $data = json_decode($this->fetch($url), true);
        if (!is_array($data)) {
            throw new WidthxAuthException("invalid JSON from {$url}");
        }
        $this->store($key, $data, $ttl);
        return $data;
    }

    private function fetch(string $url): string
    {
        try {
            $res = $this->client->request('GET', $url, [
                'headers' => ['Accept' => 'application/json'],
                'timeout' => 10,
                'connect_timeout' => 5,
                'allow_redirects' => ['max' => 3, 'protocols' => ['https'], 'strict' => true, 'referer' => false],
                'stream' => true,
            ]);
            $length = $res->getHeaderLine('Content-Length');
            if ($length !== '' && (int) $length > self::MAX_BODY_BYTES) {
                throw new WidthxAuthException("response from {$url} is too large");
            }
            $stream = $res->getBody();
            $body = '';
            while (!$stream->eof() && strlen($body) <= self::MAX_BODY_BYTES) {
                $chunk = $stream->read(65536);
                if ($chunk === '') {
                    break;
                }
                $body .= $chunk;
            }
            $stream->close();
        } catch (GuzzleException | \RuntimeException $e) {
            if ($e instanceof WidthxAuthException) {
                throw $e;
            }
            throw new WidthxAuthException("request to {$url} failed", 0, $e);
        }
        if ($res->getStatusCode() !== 200) {
            throw new WidthxAuthException("request to {$url} returned HTTP {$res->getStatusCode()}");
        }
        if (strlen($body) > self::MAX_BODY_BYTES) {
            throw new WidthxAuthException("response from {$url} is too large");
        }
        return $body;
    }

    private function remember(string $key, int $localTtl): mixed
    {
        if (isset($this->memory[$key]) && $this->memory[$key][0] > time()) {
            return $this->memory[$key][1];
        }
        unset($this->memory[$key]);
        $cached = $this->cache?->get($key);
        if ($cached !== null) {
            $this->memory[$key] = [time() + $localTtl, $cached];
        }
        return $cached;
    }

    private function store(string $key, mixed $value, int $ttl): void
    {
        $this->memory[$key] = [time() + $ttl, $value];
        $this->cache?->set($key, $value, $ttl);
    }
}
