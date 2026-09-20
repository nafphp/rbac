<?php

declare(strict_types=1);

namespace Naf\Rbac\Definition;

use Naf\Rbac\Contracts\PermissionInterface;

/**
 * A permission written out in place, rather than as a class of its own.
 *
 * The same contract either way. A package declaring twenty of them reads better
 * as a list than as twenty files; one declaring two, or one that wants to name
 * its permission by `::class` in the checks, is better off extending
 * `Permission`. Both end up in the same registry and behave identically.
 */
final readonly class PermissionDefinition implements PermissionInterface
{
    /**
     * @param string $name        Stored in rbac_role_permissions, e.g. users.invite
     * @param string $label       Short label for the role editor
     * @param string $description What holding it actually allows
     * @param string $group       Heading the editor files it under
     * @param int    $index       Sort value within its group, ascending
     */
    public function __construct(
        private string $name,
        private string $label,
        private string $description = '',
        private string $group = 'Allgemein',
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

    public function getGroup(): string
    {
        return $this->group;
    }

    public function getOrder(): int
    {
        return $this->index;
    }
}
