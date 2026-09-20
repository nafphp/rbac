<?php

declare(strict_types=1);

namespace Naf\Rbac;

use Naf\Rbac\Registry\PermissionRegistry;
use Naf\Rbac\Registry\RoleRegistry;

use function Naf\app;

/**
 * What this installation knows how to grant.
 *
 * Reachable from any plugin's bootstrap, whatever order the plugins boot in:
 * the registries have no dependencies of their own, so they are created on first
 * ask rather than waiting for this package's own bootstrap to have run. A
 * package that declares a permission must not have to know whether it comes
 * before or after the one that stores them.
 *
 * Deliberately not wrapped in function_exists checks. Plugins are registered
 * before anything else runs, so these names are taken first and taken once; a
 * second declaration afterwards is somebody shadowing the package's own helpers,
 * and the fatal error that follows says so at the line that caused it.
 */
function permissions(): PermissionRegistry
{
    $container = app()->container();

    if (!$container->has(PermissionRegistry::class)) {
        $container->set(PermissionRegistry::class, new PermissionRegistry());
    }

    return $container->get(PermissionRegistry::class);
}

/** The roles a host ships with, and the kinds of place they may be granted in. */
function roles(): RoleRegistry
{
    $container = app()->container();

    if (!$container->has(RoleRegistry::class)) {
        $container->set(RoleRegistry::class, new RoleRegistry(permissions()));
    }

    return $container->get(RoleRegistry::class);
}

/**
 * The roles and permissions themselves.
 *
 * Needs a database, so unlike the two registries this is a request-time thing:
 * call it from a controller or a view, not from a bootstrap.
 */
function rbac(): Rbac
{
    return app()->container()->get(Rbac::class);
}
