<?php

declare(strict_types=1);

namespace Naf\Rbac\Permissions;

use Naf\Rbac\Definition\Permission;

/**
 * The one permission this package needs for its own rules to mean anything.
 *
 * Named by class wherever it is checked, so a rename is a refactoring and a
 * typo is a fatal rather than a check that quietly never passes.
 */
final class ManageRoles extends Permission
{
    public const string KEY = 'rbac.manage';

    public function getKey(): string
    {
        return self::KEY;
    }

    public function getLabel(): string
    {
        return 'Rollen und Rechte verwalten';
    }

    public function getDescription(): string
    {
        return 'Rollen anlegen, ändern und an Personen vergeben.';
    }

    public function getGroup(): string
    {
        return 'Verwaltung';
    }

    public function getOrder(): int
    {
        return 10;
    }
}
