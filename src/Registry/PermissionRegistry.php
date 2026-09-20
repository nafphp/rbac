<?php

declare(strict_types=1);

namespace Naf\Rbac\Registry;

use InvalidArgumentException;
use Naf\Rbac\Contracts\PermissionInterface;

/**
 * What this installation knows how to grant.
 *
 * Plugins declare here during boot, before anything reads it:
 *
 *     app()->container()->get(PermissionRegistry::class)->add(InviteUsers::class);
 *
 * The registry is the truth about the vocabulary. The database stores only the
 * grants, so a permission no package declares any more grants nothing and comes
 * back the moment its package does.
 */
final class PermissionRegistry
{
    /** @var array<string, PermissionInterface> */
    private array $permissions = [];

    /**
     * Declare one or more, by class name or as an instance.
     *
     * @param class-string<PermissionInterface>|PermissionInterface ...$permissions
     */
    public function add(string|PermissionInterface ...$permissions): self
    {
        foreach ($permissions as $permission) {
            $instance = $this->instance($permission);

            if (trim($instance->getKey()) === '') {
                throw new InvalidArgumentException(sprintf(
                    'The permission %s has no name.',
                    $instance::class,
                ));
            }

            $this->permissions[$instance->getKey()] = $instance;
        }

        return $this;
    }

    /** @return array<string, PermissionInterface> ordered by group, then order, then name */
    public function all(): array
    {
        $sorted = $this->permissions;
        uasort(
            $sorted,
            static fn(PermissionInterface $left, PermissionInterface $right) => [
                $left->getGroup(), $left->getOrder(), $left->getKey(),
            ] <=> [$right->getGroup(), $right->getOrder(), $right->getKey()],
        );

        return $sorted;
    }

    /** @return array<string, array<string, PermissionInterface>> group to its permissions */
    public function grouped(): array
    {
        $groups = [];
        foreach ($this->all() as $name => $permission) {
            $groups[$permission->getGroup()][$name] = $permission;
        }

        return $groups;
    }

    public function knows(string $permission): bool
    {
        return isset($this->permissions[$permission]);
    }

    /**
     * The stored name of a permission, whether it arrives as a class or already
     * as one.
     *
     * A class that is not declared is still resolved: a role may name a
     * permission its own package brings, and the order the two boot in is not
     * something either of them decides.
     *
     * @param class-string<PermissionInterface>|string|PermissionInterface $permission
     */
    public function nameOf(string|PermissionInterface $permission): string
    {
        if ($permission instanceof PermissionInterface) {
            return $permission->getKey();
        }

        return class_exists($permission) ? $this->instance($permission)->getKey() : $permission;
    }

    /** @param class-string<PermissionInterface>|PermissionInterface $permission */
    private function instance(string|PermissionInterface $permission): PermissionInterface
    {
        if ($permission instanceof PermissionInterface) {
            return $permission;
        }

        if (!class_exists($permission) || !is_a($permission, PermissionInterface::class, true)) {
            throw new InvalidArgumentException(sprintf(
                '"%s" is not a %s.',
                $permission,
                PermissionInterface::class,
            ));
        }

        return new $permission();
    }
}
