<?php

declare(strict_types=1);

namespace Naf\Rbac\Definition;

use Naf\Rbac\Contracts\PermissionInterface;

/**
 * The usual permission: a name, a label, and sensible answers for the rest.
 *
 *     final class InviteUsers extends Permission
 *     {
 *         public function getKey(): string  { return 'users.invite'; }
 *         public function getLabel(): string { return 'Nutzer einladen'; }
 *         public function getGroup(): string { return 'Nutzer'; }
 *     }
 */
abstract class Permission implements PermissionInterface
{
    public function getDescription(): string
    {
        return '';
    }

    public function getGroup(): string
    {
        return 'Allgemein';
    }

    public function getOrder(): int
    {
        return 100;
    }
}
