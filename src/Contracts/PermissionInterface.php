<?php

declare(strict_types=1);

namespace Naf\Rbac\Contracts;

/**
 * One thing somebody may be allowed to do.
 *
 * A class rather than a value in a list, so that a plugin can name it by
 * `::class` and a rename is a refactoring instead of a search. What is stored
 * is still `name()`, because a grant has to outlive the class that declared it
 * -- uninstall the plugin and the row stays, meaning nothing until it is back.
 *
 * Extend `Naf\Rbac\Definition\Permission` unless you need something else; it
 * answers everything but the name and the label for you.
 */
interface PermissionInterface
{
    /** Stored in rbac_role_permissions, e.g. users.invite. Never change it lightly. */
    public function getKey(): string;

    /** Short label for the role editor. */
    public function getLabel(): string;

    /** What holding it actually allows, for the person deciding. */
    public function getDescription(): string;

    /** Heading the editor files it under. */
    public function getGroup(): string;

    /** Sort value within the group, ascending. */
    public function getOrder(): int;
}
