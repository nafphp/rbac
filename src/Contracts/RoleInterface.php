<?php

declare(strict_types=1);

namespace Naf\Rbac\Contracts;

/**
 * A named collection of permissions, and where it may be handed out.
 *
 * The permissions are class names, so a role that names one which does not
 * exist is an error at boot rather than a role that quietly grants less than it
 * says.
 *
 * Extend `Naf\Rbac\Definition\Role` for the usual case.
 */
interface RoleInterface
{
    /** Stable key, e.g. admin. Rules and code may name it. */
    public function getKey(): string;

    public function getLabel(): string;

    public function getDescription(): string;

    /**
     * What it carries when it is first written.
     *
     * A starting point, not a standing instruction: an installation that
     * changes what the role holds keeps that across upgrades.
     *
     * @return list<class-string<PermissionInterface>|string>
     */
    public function getPermissions(): array;

    /**
     * Where it means something: empty for the installation as a whole, or the
     * kind of thing it attaches to, such as "project".
     */
    public function getScopeType(): string;

    public function getOrder(): int;
}
