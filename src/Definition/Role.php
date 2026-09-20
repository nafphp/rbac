<?php

declare(strict_types=1);

namespace Naf\Rbac\Definition;

use Naf\Rbac\Contracts\PermissionInterface;
use Naf\Rbac\Contracts\RoleInterface;

/**
 * The usual role: a name, a label, and the permissions it carries.
 *
 *     final class Editor extends Role
 *     {
 *         public function getKey(): string  { return 'editor'; }
 *         public function getLabel(): string { return 'Redaktion'; }
 *
 *         public function getPermissions(): array
 *         {
 *             return [WriteArticles::class, PublishArticles::class];
 *         }
 *     }
 */
abstract class Role implements RoleInterface
{
    public function getDescription(): string
    {
        return '';
    }

    /** @return list<class-string<PermissionInterface>|string> */
    public function getPermissions(): array
    {
        return [];
    }

    public function getScopeType(): string
    {
        return '';
    }

    public function getOrder(): int
    {
        return 100;
    }
}
