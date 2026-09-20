<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Rbac\Policy\PrivilegePolicy;

/** Each rule, once, as the thing it prevents. */
final class PrivilegePolicyTest extends PolicyTestCase
{
    public function testSomebodyWithoutTheManagingPermissionCannotAssignAnything(): void
    {
        $plain  = $this->role('member', ['tickets.write']);
        $actor  = $this->person(1, [$plain]);
        $target = $this->person(2, [$plain]);

        $this->assertDenied(
            'missing_permission',
            fn() => $this->policy->assertAssignment($actor, $target, [$plain]),
        );
    }

    public function testNobodyHandsOutWhatTheyDoNotHold(): void
    {
        $admin    = $this->role('admin', [self::LOCKOUT, 'users.view']);
        $deputy   = $this->role('deputy', [self::LOCKOUT]);
        $powerful = $this->role('powerful', [self::LOCKOUT, 'billing.manage']);

        $this->person(1, [$admin]);
        $actor  = $this->person(2, [$deputy]);
        $target = $this->person(3, []);

        $this->assertDenied(
            'beyond_actor_reach',
            fn() => $this->policy->assertAssignment($actor, $target, [$powerful]),
        );
    }

    /**
     * The long way round the rule above: strip the account first, then rebuild it.
     */
    public function testNobodyManagesAnAccountThatHoldsMoreThanTheyDo(): void
    {
        $deputy   = $this->role('deputy', [self::LOCKOUT]);
        $powerful = $this->role('powerful', [self::LOCKOUT, 'billing.manage']);

        $this->person(1, [$powerful]);
        $actor  = $this->person(2, [$deputy]);
        $target = $this->person(3, [$powerful]);

        $this->assertDenied(
            'beyond_actor_reach',
            fn() => $this->policy->assertAssignment($actor, $target, [$deputy]),
        );
    }

    public function testChangingYourOwnRolesNeedsSayingSo(): void
    {
        $hr    = $this->role('hr', [self::LOCKOUT]);
        $actor = $this->person(1, [$hr]);
        $this->person(2, [$hr]);

        $this->assertDenied(
            'self_assignment',
            fn() => $this->policy->assertAssignment($actor, $actor, [$hr]),
        );
    }

    /**
     * Someone who may cannot gain anything by it.
     *
     * Rule 2 applies to yourself like to anybody else, which is what makes this
     * safe to allow at all: the most it can do is rearrange or give up what is
     * already held.
     */
    public function testSomebodyAllowedToChangeTheirOwnRolesStillCannotGrantThemselvesMore(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT, PrivilegePolicy::MANAGE_OWN]);
        $rich  = $this->role('rich', [self::LOCKOUT, 'billing.manage']);
        $actor = $this->person(1, [$admin]);
        $this->person(2, [$admin]);

        // Allowed: nothing they do not already hold.
        $this->policy->assertAssignment($actor, $actor, [$admin]);

        $this->assertDenied(
            'beyond_actor_reach',
            fn() => $this->policy->assertAssignment($actor, $actor, [$rich]),
        );
    }

    /** And not a way to step off the last set of keys. */
    public function testTheLastAdministratorCannotStepDownFromThemselves(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT, PrivilegePolicy::MANAGE_OWN]);
        $plain = $this->role('member', []);
        $actor = $this->person(1, [$admin]);

        $this->assertDenied(
            'last_keeper',
            fn() => $this->policy->assertAssignment($actor, $actor, [$plain]),
        );
    }

    /**
     * Taking the managing role off somebody is fine, because whoever does it
     * still holds it -- an assignment can never empty an installation.
     */
    public function testAnAdministratorMayBeStrippedByAnother(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, 'tickets.write']);
        $plain  = $this->role('member', ['tickets.write']);
        $actor  = $this->person(1, [$admin]);
        $target = $this->person(2, [$admin]);

        $this->policy->assertAssignment($actor, $target, [$plain]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * The invariant itself, for the paths that live in the host.
     *
     * Deleting or deactivating an account is not this package's to perform, but
     * whether it may happen is: an installation nobody can administer any more
     * is not a state a host should be able to reach one request at a time.
     */
    public function testTheInstallationAlwaysKeepsSomebodyWhoCanAdminister(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT]);
        $alice = $this->person(1, [$admin]);
        $bob   = $this->person(2, [$admin]);

        // Two hold it, so either may go.
        $this->policy->assertSomebodyKeepsTheKeys([$alice]);
        $this->policy->assertSomebodyKeepsTheKeys([$bob]);

        // Both at once would leave none.
        $this->assertDenied(
            'last_keeper',
            fn() => $this->policy->assertSomebodyKeepsTheKeys([$alice, $bob]),
        );

        $this->assignments->assign($bob, []);

        $this->assertDenied(
            'last_keeper',
            fn() => $this->policy->assertSomebodyKeepsTheKeys([$alice]),
        );
    }

    public function testARoleMayNotBeGivenPermissionsItsEditorLacks(): void
    {
        $deputy = $this->role('deputy', [self::LOCKOUT]);
        $actor  = $this->person(1, [$deputy]);

        $this->assertDenied(
            'beyond_actor_reach',
            fn() => $this->policy->assertRoleChange($actor, null, [self::LOCKOUT, 'billing.manage']),
        );
    }

    public function testARoleAboveTheEditorsLevelCannotBeEditedAtAll(): void
    {
        $deputy   = $this->role('deputy', [self::LOCKOUT]);
        $powerful = $this->role('powerful', [self::LOCKOUT, 'billing.manage']);
        $actor    = $this->person(1, [$deputy]);

        $this->assertDenied(
            'beyond_actor_reach',
            fn() => $this->policy->assertRoleChange($actor, $powerful, [self::LOCKOUT]),
        );
    }

    public function testTheRoleThatCarriesTheKeysCannotBeEmptiedWhileItIsTheOnlyOne(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT]);
        $actor = $this->person(1, [$admin]);

        $this->assertDenied(
            'last_keeper',
            fn() => $this->policy->assertRoleChange($actor, $admin, []),
        );
    }

    public function testADeclaredRoleIsNotDeletable(): void
    {
        $admin = $this->role('admin', [self::LOCKOUT], system: true);
        $extra = $this->role('extra', [self::LOCKOUT], system: true);
        $actor = $this->person(1, [$admin]);
        $this->person(2, [$extra]);

        $this->assertDenied('system_role', fn() => $this->policy->assertRoleDeletion($actor, $extra));
    }

    public function testAnOrdinaryChangeIsAllowed(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, 'users.view', 'tickets.write']);
        $plain  = $this->role('member', ['tickets.write']);
        $actor  = $this->person(1, [$admin]);
        $target = $this->person(2, []);

        $this->policy->assertAssignment($actor, $target, [$plain]);
        $this->policy->assertRoleChange($actor, $plain, ['users.view']);

        $this->expectNotToPerformAssertions();
    }
}
