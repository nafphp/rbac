<?php

declare(strict_types=1);

namespace Naf\Rbac\Definition;

use Naf\Rbac\Contracts\PermissionInterface;
use Naf\Rbac\Contracts\RoleInterface;

/**
 * A role written out in place, rather than as a class of its own.
 *
 * Its permissions may be names or permission class names, mixed freely: the
 * registry resolves a class to the name it stores, so a role can point at the
 * class a plugin brings and keep working when that plugin is not installed.
 */
final readonly class RoleDefinition implements RoleInterface
{
    /**
     * @param string                                              $name        Stable key, e.g. admin
     * @param string                                              $label       Shown wherever it is offered
     * @param string                                              $description What the role is for
     * @param list<class-string<PermissionInterface>|string>       $permissions Granted when first written
     * @param string                                              $scopeType   Empty, or the kind it attaches to
     * @param int                                                 $index       Sort value, ascending
     */
    public function __construct(
        private string $name,
        private string $label,
        private string $description = '',
        private array $permissions = [],
        private string $scopeType = '',
        private int $index = 100,
    ) {
    }

    public function getKey(): string
    {
        return $this->name;
    }

    public function getLabel(): string
    {
        return $this->label;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    /** @return list<class-string<PermissionInterface>|string> */
    public function getPermissions(): array
    {
        return $this->permissions;
    }

    public function getScopeType(): string
    {
        return $this->scopeType;
    }

    public function getOrder(): int
    {
        return $this->index;
    }
}
