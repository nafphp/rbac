<?php

declare(strict_types=1);

namespace Naf\Rbac\Identity;

use function Naf\Rbac\rbac;

/**
 * The two grant methods, answered from the stored roles.
 *
 * The whole of what a user model needs to be governed by this package. It uses
 * `getIdentifier()`, which `Naf\Auth\Identity\IdentityInterface` already
 * requires, so there is nothing for the model to provide.
 *
 * Both answers are cached per request inside Rbac, so a page asking twenty
 * times costs one pair of queries. After changing somebody's grants in a
 * request that goes on to read them back, call `rbac()->forget($id)`.
 */
trait ResolvesGrants
{
    /** @return iterable<string> */
    public function getRoles(): iterable
    {
        return rbac()->rolesOf((int) $this->getIdentifier());
    }

    /** @return iterable<string> */
    public function getPermissions(): iterable
    {
        return rbac()->permissionsOf((int) $this->getIdentifier());
    }
}
