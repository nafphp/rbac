<?php

declare(strict_types=1);

use Naf\CLI\Support\CommandRegistry;
use Naf\Database\Support\MigrationRegistry;
use Naf\Rbac\Commands\SyncCommand;
use Naf\Rbac\Permissions\Everything;
use Naf\Rbac\Permissions\ManageOwnRoles;
use Naf\Rbac\Permissions\ManageRoles;
use Naf\Rbac\Policy\PrivilegePolicy;
use Naf\Rbac\Rbac;
use Naf\Rbac\Repository\AssignmentRepository;
use Naf\Rbac\Repository\RoleRepository;

use function Naf\app;
use function Naf\config;
use function Naf\Rbac\permissions;
use function Naf\Rbac\roles;

$container = app()->container();

MigrationRegistry::addPath(__DIR__ . '/src/Migrations');

$container->set(RoleRepository::class, static fn() => new RoleRepository($container->get(PDO::class)));
$container->set(
    AssignmentRepository::class,
    static fn() => new AssignmentRepository($container->get(PDO::class), permissions()),
);
$container->set(
    PrivilegePolicy::class,
    static fn() => new PrivilegePolicy(
        $container->get(RoleRepository::class),
        $container->get(AssignmentRepository::class),
        (string) config('rbac:lockout_permission', 'rbac.manage'),
    ),
);
$container->set(
    Rbac::class,
    static fn() => new Rbac(
        permissions(),
        roles(),
        $container->get(RoleRepository::class),
        $container->get(AssignmentRepository::class),
        $container->get(PrivilegePolicy::class),
    ),
);

/*
 * Only when naf/cli is installed. A host that runs no CLI still gets the whole
 * package; it just writes its declared roles itself, or never declares any.
 */
if (class_exists(CommandRegistry::class) && $container->has(CommandRegistry::class)) {
    $container->get(CommandRegistry::class)->add(SyncCommand::class);
}

// What this package needs for its own rules to mean anything. Everything else
// a host declares for itself, the same way: by class.
permissions()->add(Everything::class, ManageRoles::class, ManageOwnRoles::class);
