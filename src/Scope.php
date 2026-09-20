<?php

declare(strict_types=1);

namespace Naf\Rbac;

use InvalidArgumentException;

/**
 * Where a grant applies.
 *
 * Three shapes, and the whole of the tenancy is which of them covers which:
 *
 *   Scope::everywhere()        ''             an installation-wide grant
 *   Scope::allOf('project')    'project:*'    on every board there is
 *   Scope::of('project', 7)    'project:7'    on that one board
 *
 * A value object rather than a string, because `covers()` is the one rule that
 * decides what somebody may do where, and a rule spread across three string
 * comparisons in three files is a rule that will disagree with itself.
 */
final readonly class Scope
{
    private const string WILDCARD = '*';

    private function __construct(public string $type, public string $id)
    {
    }

    public static function everywhere(): self
    {
        return new self('', '');
    }

    /** Every instance of a kind: maintainer on all boards, rather than on one. */
    public static function allOf(string $type): self
    {
        return new self(self::type($type), self::WILDCARD);
    }

    public static function of(string $type, int|string $id): self
    {
        $id = trim((string) $id);
        if ($id === '' || $id === self::WILDCARD) {
            throw new InvalidArgumentException('A scope needs a concrete id; use allOf() for every instance.');
        }

        return new self(self::type($type), $id);
    }

    /** Read one back from storage. Anything unparseable is the empty scope. */
    public static function parse(string $stored): self
    {
        $stored = trim($stored);
        if ($stored === '' || !str_contains($stored, ':')) {
            return self::everywhere();
        }

        [$type, $id] = explode(':', $stored, 2);

        return $id === self::WILDCARD ? self::allOf($type) : self::of($type, $id);
    }

    public function isEverywhere(): bool
    {
        return $this->type === '';
    }

    public function isAllOfAKind(): bool
    {
        return $this->type !== '' && $this->id === self::WILDCARD;
    }

    /**
     * Whether a grant held at this scope has effect at $there.
     *
     * Installation-wide covers everything: somebody who may do a thing anywhere
     * may do it on any board too. That is a decision and not an accident -- the
     * alternative, an administrator locked out of a board, is a support request
     * rather than a safeguard. A host that wants the separation names the two
     * abilities differently instead.
     */
    public function covers(self $there): bool
    {
        if ($this->isEverywhere()) {
            return true;
        }

        if ($this->type !== $there->type) {
            return false;
        }

        return $this->isAllOfAKind() || $this->id === $there->id;
    }

    public function __toString(): string
    {
        return $this->isEverywhere() ? '' : $this->type . ':' . $this->id;
    }

    private static function type(string $type): string
    {
        $type = trim($type);
        if ($type === '' || str_contains($type, ':')) {
            throw new InvalidArgumentException('A scope type must be non-empty and free of colons.');
        }

        return $type;
    }
}
