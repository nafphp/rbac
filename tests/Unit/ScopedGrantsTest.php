<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Rbac\Scope;

/**
 * The same person, different places, different answers.
 *
 * This is the case the whole scope column exists for: maintainer on one board,
 * ordinary member on the next, and an administrator who is neither yet may do
 * both.
 */
final class ScopedGrantsTest extends PolicyTestCase
{
    private const string MAINTAIN = 'board.settings';
    private const string WRITE    = 'tickets.write';

    public function testOnePersonHoldsDifferentPermissionsOnDifferentBoards(): void
    {
        $maintainer = $this->role('maintainer', [self::MAINTAIN, self::WRITE], scopeType: 'project');
        $member     = $this->role('member', [self::WRITE], scopeType: 'project');

        $this->person(7, [$maintainer], Scope::of('project', 1));
        $this->person(7, [$member], Scope::of('project', 2));

        self::assertSame(
            [self::MAINTAIN, self::WRITE],
            $this->assignments->permissionsOf(7, Scope::of('project', 1)),
        );
        self::assertSame(
            [self::WRITE],
            $this->assignments->permissionsOf(7, Scope::of('project', 2)),
            'the role on one board leaked onto the other',
        );
        self::assertSame(
            [],
            $this->assignments->permissionsOf(7, Scope::of('project', 3)),
            'a board nobody was assigned to handed something out',
        );
    }

    public function testAnInstallationWideGrantReachesInsideEveryBoard(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT, self::MAINTAIN]);
        $this->person(1, [$admin]);

        self::assertTrue(
            in_array(self::MAINTAIN, $this->assignments->permissionsOf(1, Scope::of('project', 9)), true),
        );
    }

    public function testEveryBoardOfAKindIsNotTheSameAsEverywhere(): void
    {
        $maintainer = $this->role('maintainer', [self::MAINTAIN], scopeType: 'project');
        $this->person(4, [$maintainer], Scope::allOf('project'));

        self::assertSame(
            [self::MAINTAIN],
            $this->assignments->permissionsOf(4, Scope::of('project', 42)),
            'a grant on every board did not reach one of them',
        );
        self::assertSame(
            [],
            $this->assignments->permissionsOf(4, Scope::everywhere()),
            'a grant on every board became an installation-wide one',
        );
    }

    public function testManagingOneBoardIsNoAuthorityOverAnother(): void
    {
        $lead   = $this->role('lead', [self::LOCKOUT, self::WRITE], scopeType: 'project');
        $member = $this->role('member', [self::WRITE], scopeType: 'project');

        $actor = $this->person(1, [$lead], Scope::of('project', 1));
        $this->person(2, []);

        // On their own board they may hand the role out.
        $this->policy->assertAssignment($actor, 2, [$member], Scope::of('project', 1));

        $this->assertDenied(
            'missing_permission',
            fn() => $this->policy->assertAssignment($actor, 2, [$member], Scope::of('project', 2)),
        );
    }

    public function testAnInstallationWideRoleIsNotHandedOutOnASingleBoard(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT]);
        $actor = $this->person(1, [$admin]);
        $this->person(2, []);

        $this->assertDenied(
            'role_not_grantable_here',
            fn() => $this->policy->assertAssignment($actor, 2, [$admin], Scope::of('project', 1)),
        );
    }

    public function testABoardRoleIsNotHandedOutInstallationWide(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, self::WRITE]);
        $member = $this->role('member', [self::WRITE], scopeType: 'project');
        $actor  = $this->person(1, [$admin]);
        $this->person(2, []);

        $this->assertDenied(
            'role_not_grantable_here',
            fn() => $this->policy->assertAssignment($actor, 2, [$member], Scope::everywhere()),
        );
    }

    /**
     * Editing somebody on one board says nothing about the installation.
     *
     * The guard that keeps the last administrator asks only about grants that
     * hold everywhere. Without that limit this refuses a board lead's ordinary
     * edit whenever the person being edited happens to administer the
     * installation -- the kind of denial nobody can act on, because what it
     * objects to is not what was being changed.
     */
    public function testEditingSomebodyOnABoardIsNotRefusedBecauseTheyAdministerTheInstallation(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, self::WRITE, self::MAINTAIN]);
        $lead   = $this->role('lead', [self::LOCKOUT, self::WRITE, self::MAINTAIN], scopeType: 'project');
        $member = $this->role('member', [self::WRITE], scopeType: 'project');

        $actor = $this->person(1, [$lead], Scope::of('project', 1));
        // The only administrator of the installation, and a member of board 1.
        $target = $this->person(2, [$admin]);
        $this->assignments->assign($target, [$member], Scope::of('project', 1));

        $this->policy->assertAssignment($actor, $target, [], Scope::of('project', 1));

        $this->expectNotToPerformAssertions();
    }

    /**
     * A kind this package has never heard of, working the same.
     *
     * Nothing here says "project" anywhere but in the test: the type is a
     * string the host chooses, so attaching roles to teams, tenants or single
     * tickets needs a ScopeSource registration and no change in the package.
     */
    public function testAnyKindOfThingCanCarryRoles(): void
    {
        $lead   = $this->role("team-lead", [self::MAINTAIN], scopeType: "team");
        $member = $this->role("board-member", [self::WRITE], scopeType: "project");

        $this->person(9, [$lead], Scope::of("team", "design"));
        $this->person(9, [$member], Scope::of("project", 4));

        self::assertSame([self::MAINTAIN], $this->assignments->permissionsOf(9, Scope::of("team", "design")));
        self::assertSame([self::WRITE], $this->assignments->permissionsOf(9, Scope::of("project", 4)));
        self::assertSame(
            [],
            $this->assignments->permissionsOf(9, Scope::of("team", "marketing")),
            "a grant on one team reached another",
        );
    }

    /**
     * Editing a role is installation-wide however you reach it, because the
     * role is one object that every board holding it shares.
     */
    public function testABoardLeadCannotRewriteTheRoleItselfForEverybody(): void
    {
        $lead = $this->role('lead', [self::LOCKOUT, self::WRITE], scopeType: 'project');
        $this->role('member', [self::WRITE], scopeType: 'project');
        $actor = $this->person(1, [$lead], Scope::of('project', 1));

        $this->assertDenied(
            'missing_permission',
            fn() => $this->policy->assertRoleChange($actor, null, [self::WRITE]),
        );
    }
}
