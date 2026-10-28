<?php

declare(strict_types=1);

namespace Widthx\Auth\Tests;

use Psr\SimpleCache\CacheInterface;

/** Minimal PSR-16 cache shared between Widthx instances to simulate separate PHP requests. */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{0: mixed, 1: ?int}> */
    public array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        $item = $this->items[$key] ?? null;
        if ($item === null || ($item[1] !== null && $item[1] <= time())) {
            return $default;
        }
        return $item[0];
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->items[$key] = [$value, is_int($ttl) ? time() + $ttl : null];
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->items = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->get($key, $default);
        }
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }
}
