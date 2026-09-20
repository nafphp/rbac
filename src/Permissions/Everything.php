<?php

declare(strict_types=1);

namespace Naf\Rbac\Permissions;

use Naf\Rbac\Definition\Permission;

/**
 * Holding this is holding every other permission.
 *
 * A role that carries it does not need its list kept up to date: the moment a
 * package declares a permission, whoever holds this one has it. Writing the
 * full list onto such a role instead would make it a snapshot, and the next
 * installed package would quietly fall outside it -- the administrator would
 * lose a right by gaining a feature.
 *
 * This is a permission, not a special role. Which role carries it is an
 * installation's decision, and taking it away is an ordinary edit rather than a
 * rename that silently changes what the system enforces.
 */
final class Everything extends Permission
{
    public const string KEY = 'rbac.all';

    public function getKey(): string
    {
        return self::KEY;
    }

    public function getLabel(): string
    {
        return 'Alles dürfen';
    }

    public function getDescription(): string
    {
        return 'Trägt jedes Recht dieser Installation, auch die, die ein Paket später mitbringt.';
    }

    public function getGroup(): string
    {
        return 'Verwaltung';
    }

    public function getOrder(): int
    {
        return 1;
    }
}
