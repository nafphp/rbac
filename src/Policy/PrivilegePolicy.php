<?php

declare(strict_types=1);

namespace Naf\Rbac\Policy;

use Naf\Rbac\Exceptions\PrivilegedActionDenied;
use Naf\Rbac\Repository\AssignmentRepository;
use Naf\Rbac\Repository\RoleRepository;
use Naf\Rbac\Scope;

/**
 * The rules for handing out power, in one readable place.
 *
 * Every method either returns silently or throws. They are assertions, not
 * questions: a caller treats a normal return as "allowed", so a rule that
 * forgets to throw fails open. That is why they read as a list of denials.
 *
 * Five ideas carry all of it:
 *
 * 1. You need the managing permission -- in the place you are acting.
 * 2. You cannot hand out what you do not hold there. This one subsumes the rule
 *    other systems write separately as "only an administrator may make
 *    administrators": if only they hold the managing permission, only they can
 *    grant a role that carries it.
 * 3. You cannot manage an account that holds something you do not. Otherwise the
 *    way around rule 2 is to take somebody's roles away and give them back.
 * 4. A role is granted only where it means something. An installation-wide role
 *    on one board would be a grant whose reach nobody could predict.
 * 5. Somebody has to be left who can still do this. The last role carrying the
 *    managing permission cannot be emptied or deleted.
 *
 * Changing your own roles is refused outright rather than reasoned about: the
 * rules above would allow it, and an account quietly widening itself is exactly
 * what an audit later cannot distinguish from an intrusion.
 *
 * Editing a role is deliberately not scoped. A role is one object held in many
 * places, so changing what it carries reaches every one of them -- which is
 * authority over the installation, not over a board.
 */
final readonly class PrivilegePolicy
{
    /** Held by whoever may rearrange their own roles; see assertAssignment. */
    public const string MANAGE_OWN = 'rbac.manage.own';

    public function __construct(
        private RoleRepository $roles,
        private AssignmentRepository $assignments,
        private string $lockoutPermission,
    ) {
    }

    /**
     * @param list<int> $roleIds the roles the target is to hold in $at afterwards
     */
    public function assertAssignment(int $actorId, int $targetId, array $roleIds, ?Scope $at = null): void
    {
        $at    = $at ?? Scope::everywhere();
        $actor = $this->assignments->permissionsOf($actorId, $at);

        $this->require($actor);

        /*
         * Changing your own roles is a permission rather than a prohibition.
         *
         * It cannot be used to gain anything: rule 2 applies to yourself like to
         * anybody else, so the most you can do is rearrange or give up what you
         * already hold. What it is good for is an administrator who hands out
         * roles that must not hand themselves out -- HR, project management --
         * and that difference is a grant, not a line of code.
         *
         * The guard below still applies, so this is not a way to step off the
         * last set of keys either.
         */
        if ($actorId === $targetId && !in_array(self::MANAGE_OWN, $actor, true)) {
            $this->deny('self_assignment', 'Du kannst deine eigenen Rollen nicht ändern.');
        }

        if ($actorId !== $targetId) {
            $this->assertWithinReach(
                $actor,
                $this->assignments->permissionsOf($targetId, $at),
                'verwalten',
            );
        }
        $this->assertGrantableAt($roleIds, $at);
        $after = $this->permissionsOfRoles($roleIds);
        $this->assertWithinReach($actor, $after, 'vergeben');

        /*
         * Whatever this takes away, somebody has to be left who can give it
         * back. Under the rules above an assignment is hard to lock an
         * installation out with -- the actor holds the permission here and may
         * not target themselves, so they remain. That is a conclusion, though,
         * and it rests on a different rule staying true. An invariant that can
         * be broken by relaxing something else somewhere else is not one, so it
         * is asserted where the taking away happens.
         *
         * Only for an installation-wide change, because that is the only kind
         * that can take the last one away. Editing somebody's roles on one
         * board leaves what they hold everywhere untouched -- asking there
         * would refuse a board lead's ordinary edit because the person they are
         * editing happens to administer the installation.
         */
        if (
            $at->isEverywhere()
            && !in_array($this->lockoutPermission, $after, true)
            && in_array($this->lockoutPermission, $this->assignments->permissionsOf($targetId), true)
        ) {
            $this->assertOthersKeepTheKeys([$targetId]);
        }
    }

    /**
     * @param list<string> $permissions the permissions the role is to carry afterwards
     */
    public function assertRoleChange(int $actorId, ?int $roleId, array $permissions): void
    {
        $actor = $this->assignments->permissionsOf($actorId, Scope::everywhere());
        $this->require($actor);
        $this->assertWithinReach($actor, $permissions, 'vergeben');

        if ($roleId === null) {
            return;
        }

        $role = $this->roles->find($roleId);
        if ($role === null) {
            $this->deny('role_not_found', 'Diese Rolle gibt es nicht.');
        }

        // Without this, a role above the actor's level could be emptied and
        // refilled -- the long way round rule 2.
        $this->assertWithinReach($actor, $role['permissions'], 'bearbeiten');

        if (
            in_array($this->lockoutPermission, $role['permissions'], true)
            && !in_array($this->lockoutPermission, $permissions, true)
        ) {
            $this->assertOthersKeepTheKeys($this->assignments->holdersOf($role['name']));
        }
    }

    public function assertRoleDeletion(int $actorId, int $roleId): void
    {
        $actor = $this->assignments->permissionsOf($actorId, Scope::everywhere());
        $this->require($actor);

        $role = $this->roles->find($roleId);
        if ($role === null) {
            $this->deny('role_not_found', 'Diese Rolle gibt es nicht.');
        }

        if ($role['system']) {
            $this->deny('system_role', 'Mitgelieferte Rollen bleiben erhalten.');
        }

        $this->assertWithinReach($actor, $role['permissions'], 'löschen');

        if (in_array($this->lockoutPermission, $role['permissions'], true)) {
            $this->assertOthersKeepTheKeys($this->assignments->holdersOf($role['name']));
        }
    }

    /**
     * Refuse anything that would leave nobody able to hand out roles.
     *
     * Public because it is an invariant of the installation and not of one
     * screen: every way an account can stop counting -- deleted, deactivated,
     * merged away -- has to ask this before it acts, and each of those lives in
     * the host rather than here.
     *
     * The assignment path does not call it, and that is a conclusion rather
     * than an oversight: whoever assigns holds the permission themselves and
     * may not target themselves, so one holder always remains. Deleting is
     * different -- there the actor can remove the only other one and then
     * themselves, one request at a time.
     *
     * @param list<int> $losing accounts about to stop counting
     */
    public function assertSomebodyKeepsTheKeys(array $losing): void
    {
        $this->assertOthersKeepTheKeys($losing);
    }

    /**
     * @param list<int> $roleIds
     * @return list<string>
     */
    private function permissionsOfRoles(array $roleIds): array
    {
        $permissions = [];
        foreach ($this->roles->all() as $role) {
            if (in_array($role['id'], $roleIds, true)) {
                $permissions = [...$permissions, ...$role['permissions']];
            }
        }

        return array_values(array_unique($permissions));
    }

    /** @param list<int> $roleIds */
    private function assertGrantableAt(array $roleIds, Scope $at): void
    {
        foreach ($this->roles->all() as $role) {
            if (!in_array($role['id'], $roleIds, true)) {
                continue;
            }

            $fits = $role['scopeType'] === '' ? $at->isEverywhere() : $role['scopeType'] === $at->type;
            if ($fits) {
                continue;
            }

            $this->deny(
                'role_not_grantable_here',
                sprintf(
                    'Die Rolle "%s" gilt %s und kann hier nicht vergeben werden.',
                    $role['label'],
                    $role['scopeType'] === '' ? 'für die ganze Installation' : 'je ' . $role['scopeType'],
                ),
            );
        }
    }

    /** @param list<string> $actor */
    private function require(array $actor): void
    {
        if (!in_array($this->lockoutPermission, $actor, true)) {
            $this->deny('missing_permission', 'Dir fehlt die Berechtigung, Rollen zu verwalten.');
        }
    }

    /**
     * @param list<string> $actor
     * @param list<string> $wanted
     */
    private function assertWithinReach(array $actor, array $wanted, string $verb): void
    {
        $beyond = array_diff($wanted, $actor);
        if ($beyond !== []) {
            $this->deny(
                'beyond_actor_reach',
                sprintf(
                    'Du kannst nur %s, was du selbst hast. Dir fehlt: %s',
                    $verb,
                    implode(', ', $beyond),
                ),
            );
        }
    }

    /**
     * Refuse when the named accounts are the only ones left who could undo it.
     *
     * @param list<int> $losing
     */
    private function assertOthersKeepTheKeys(array $losing): void
    {
        if ($this->assignments->holdersOfPermission($this->lockoutPermission) > count($losing)) {
            return;
        }

        $this->deny(
            'last_keeper',
            'Danach könnte niemand mehr Rollen verwalten. Gib die Berechtigung zuerst jemand anderem.',
        );
    }

    private function deny(string $reason, string $message): never
    {
        throw new PrivilegedActionDenied($reason, $message);
    }
}
