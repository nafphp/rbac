<?php

declare(strict_types=1);

namespace Naf\Rbac;

use Naf\Rbac\Policy\PrivilegePolicy;
use Naf\Rbac\Registry\PermissionRegistry;
use Naf\Rbac\Registry\RoleRegistry;
use Naf\Rbac\Repository\AssignmentRepository;
use Naf\Rbac\Repository\RoleRepository;

/**
 * One way in, for hosts and for the shipped screens alike.
 *
 * The grants of a signed-in person are read once per request. Without that the
 * two lookups would run for every single check, and a page that asks a dozen
 * times would pay for it a dozen times.
 */
final class Rbac
{
    /** Keyed by person and place, because the answer differs per board. @var array<string, list<string>> */
    private array $roleCache = [];

    /** @var array<string, list<string>> */
    private array $permissionCache = [];

    public function __construct(
        public readonly PermissionRegistry $permissions,
        public readonly RoleRegistry $declared,
        public readonly RoleRepository $roles,
        public readonly AssignmentRepository $assignments,
        public readonly PrivilegePolicy $policy,
    ) {
    }

    /** @return list<string> the roles that have effect in $at */
    public function rolesOf(int $userId, ?Scope $at = null): array
    {
        $at = $at ?? Scope::everywhere();

        return $this->roleCache[$this->key($userId, $at)] ??= $this->assignments->rolesOf($userId, $at);
    }

    /** @return list<string> the permissions that have effect in $at */
    public function permissionsOf(int $userId, ?Scope $at = null): array
    {
        $at = $at ?? Scope::everywhere();

        return $this->permissionCache[$this->key($userId, $at)]
            ??= $this->assignments->permissionsOf($userId, $at);
    }

    public function allows(int $userId, string $permission, ?Scope $at = null): bool
    {
        return in_array($permission, $this->permissionsOf($userId, $at), true);
    }

    /**
     * Forget what was read, after something that changed it.
     *
     * A request that hands out a role and then renders the result must not show
     * the answer it cached before the change.
     */
    public function forget(?int $userId = null): void
    {
        if ($userId === null) {
            $this->roleCache       = [];
            $this->permissionCache = [];

            return;
        }

        // Every place at once: a change in one can be reached from another, and
        // guessing which would be the kind of cache bug nobody finds.
        foreach ([...array_keys($this->roleCache), ...array_keys($this->permissionCache)] as $key) {
            if (str_starts_with((string) $key, $userId . '@')) {
                unset($this->roleCache[$key], $this->permissionCache[$key]);
            }
        }
    }

    private function key(int $userId, Scope $at): string
    {
        return $userId . '@' . $at;
    }
}
