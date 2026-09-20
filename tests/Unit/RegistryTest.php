<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use Naf\Rbac\Definition\Permission;
use Naf\Rbac\Definition\PermissionDefinition;
use Naf\Rbac\Definition\Role;
use Naf\Rbac\Definition\RoleDefinition;
use Naf\Rbac\Registry\PermissionRegistry;
use Naf\Rbac\Registry\RoleRegistry;
use PHPUnit\Framework\TestCase;

final class InviteUsers extends Permission
{
    public function getKey(): string
    {
        return 'users.invite';
    }

    public function getLabel(): string
    {
        return 'Nutzer einladen';
    }

    public function getGroup(): string
    {
        return 'Nutzer';
    }
}

final class Recruiter extends Role
{
    public function getKey(): string
    {
        return 'recruiter';
    }

    public function getLabel(): string
    {
        return 'Recruiting';
    }

    /** @return list<string> */
    public function getPermissions(): array
    {
        return [InviteUsers::class];
    }
}

/** Declaring by class, which is how a plugin hooks in. */
final class RegistryTest extends TestCase
{
    private PermissionRegistry $permissions;
    private RoleRegistry $roles;

    protected function setUp(): void
    {
        $this->permissions = new PermissionRegistry();
        $this->roles       = new RoleRegistry($this->permissions);
    }

    public function testAPluginDeclaresByClassName(): void
    {
        $this->permissions->add(InviteUsers::class);
        $this->roles->add(Recruiter::class);

        self::assertTrue($this->permissions->knows('users.invite'));
        self::assertSame(['Nutzer'], array_keys($this->permissions->grouped()));
        self::assertSame(['recruiter'], array_keys($this->roles->all()));
    }

    /**
     * A role names permissions by class, and the registry stores their keys.
     *
     * That is the whole point of the class: a typo is a fatal at boot rather
     * than a role that quietly grants one permission less than it says.
     */
    public function testARoleResolvesThePermissionClassesItNames(): void
    {
        $this->permissions->add(InviteUsers::class);
        $this->roles->add(Recruiter::class);

        self::assertSame(
            ['users.invite'],
            $this->roles->permissionsOf($this->roles->all()['recruiter']),
        );
    }

    /**
     * A role may name a permission whose package is not installed.
     *
     * The grant is stored either way and means nothing until the package is
     * back -- which is the same rule the database follows.
     */
    public function testARoleMayNameAPermissionNobodyDeclared(): void
    {
        $this->roles->add(new RoleDefinition('mixed', 'Gemischt', '', [InviteUsers::class, 'billing.manage']));

        self::assertSame(
            ['users.invite', 'billing.manage'],
            $this->roles->permissionsOf($this->roles->all()['mixed']),
        );
    }

    public function testWritingOneOutInPlaceIsTheSameThing(): void
    {
        $this->permissions->add(new PermissionDefinition('users.invite', 'Nutzer einladen', '', 'Nutzer'));

        self::assertTrue($this->permissions->knows('users.invite'));
    }

    public function testSomethingThatIsNotAPermissionIsRefusedWhereItIsWritten(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->permissions->add(self::class);
    }
}
