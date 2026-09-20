<?php

declare(strict_types=1);

namespace Naf\Rbac\Registry;

use InvalidArgumentException;
use Naf\Rbac\Contracts\RoleInterface;
use Naf\Rbac\Contracts\ScopeSourceInterface;

/**
 * The roles a host ships with, as opposed to the ones an installation made.
 *
 *     app()->container()->get(RoleRegistry::class)->add(EditorRole::class);
 *
 * A role is a collection of permissions and a place they mean something in.
 * `rbac:sync` writes what is declared here; it never overwrites what an
 * installation has since decided about a role, so declaring is a starting
 * point and not a standing instruction.
 */
final class RoleRegistry
{
    /** @var array<string, RoleInterface> */
    private array $roles = [];

    /** @var array<string, ScopeSourceInterface> */
    private array $scopes = [];

    public function __construct(private readonly PermissionRegistry $permissions)
    {
    }

    /**
     * @param class-string<RoleInterface>|RoleInterface ...$roles
     */
    public function add(string|RoleInterface ...$roles): self
    {
        foreach ($roles as $role) {
            $instance = $this->instance($role);

            if (trim($instance->getKey()) === '') {
                throw new InvalidArgumentException(sprintf('The role %s has no name.', $instance::class));
            }

            $this->roles[$instance->getKey()] = $instance;
        }

        return $this;
    }

    /**
     * Where grants may be attached, beyond the installation itself.
     *
     * Registered here because a scope is where a role means something, and a
     * role that may be granted on a board is only useful once something can say
     * which boards there are.
     */
    public function scope(ScopeSourceInterface ...$sources): self
    {
        foreach ($sources as $source) {
            $this->scopes[$source->type()] = $source;
        }

        return $this;
    }

    /** @return array<string, ScopeSourceInterface> */
    public function scopes(): array
    {
        return $this->scopes;
    }

    public function scopeSource(string $type): ?ScopeSourceInterface
    {
        return $this->scopes[$type] ?? null;
    }

    /** @return array<string, RoleInterface> ordered by order, then name */
    public function all(): array
    {
        $sorted = $this->roles;
        uasort(
            $sorted,
            static fn(RoleInterface $left, RoleInterface $right)
                => [$left->getOrder(), $left->getKey()] <=> [$right->getOrder(), $right->getKey()],
        );

        return $sorted;
    }

    /**
     * The permission names a role carries, with its classes resolved.
     *
     * @return list<string>
     */
    public function permissionsOf(RoleInterface $role): array
    {
        return array_values(array_unique(array_map(
            fn(string $permission): string => $this->permissions->nameOf($permission),
            $role->getPermissions(),
        )));
    }

    /** @param class-string<RoleInterface>|RoleInterface $role */
    private function instance(string|RoleInterface $role): RoleInterface
    {
        if ($role instanceof RoleInterface) {
            return $role;
        }

        if (!class_exists($role) || !is_a($role, RoleInterface::class, true)) {
            throw new InvalidArgumentException(sprintf('"%s" is not a %s.', $role, RoleInterface::class));
        }

        return new $role();
    }
}
