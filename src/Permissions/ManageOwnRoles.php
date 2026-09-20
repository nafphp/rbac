<?php

declare(strict_types=1);

namespace Naf\Rbac\Permissions;

use Naf\Rbac\Definition\Permission;

/** Rearranging one's own roles; see PrivilegePolicy for why that is safe. */
final class ManageOwnRoles extends Permission
{
    public const string KEY = 'rbac.manage.own';

    public function getKey(): string
    {
        return self::KEY;
    }

    public function getLabel(): string
    {
        return 'Eigene Rollen ändern';
    }

    public function getDescription(): string
    {
        return 'Die eigenen Rollen umstellen. Mehr als man selbst hat, geht auch damit nicht.';
    }

    public function getGroup(): string
    {
        return 'Verwaltung';
    }

    public function getOrder(): int
    {
        return 20;
    }
}
