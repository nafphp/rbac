<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Rbac\Definition\RoleDefinition;
use Naf\Rbac\Registry\RoleRegistry;

/**
 * What an upgrade quietly takes away, said out loud.
 *
 * A stored role keeps what this installation made of it, which is right: an
 * editor role somebody trimmed on purpose must not be handed its permissions
 * back because a package was updated. The price is that a permission declared
 * *after* the roles were written reaches nobody -- the feature behind it is
 * dead, and the only symptom is a button that does nothing for everyone.
 *
 * So the drift is reported rather than repaired. Which of the two sides is
 * right is a decision, and the installation is the one entitled to make it.
 */
final class DeclaredDriftTest extends PolicyTestCase
{
    private RoleRegistry $registry;

    protected function setUp(): void
    {
        parent::setUp();
        $this->registry = new RoleRegistry($this->permissions);
    }

    /** The case this exists for: a package added a permission after the fact. */
    public function testARoleThatLostAPermissionItsPackageDeclaresIsNamed(): void
    {
        $this->role('owner', ['write', 'comment'], system: true);

        $this->assertSame(
            ['owner' => ['delete']],
            $this->drift(['owner' => ['write', 'comment', 'delete']]),
        );
    }

    /** A role that carries everything is not worth a sentence. */
    public function testNothingIsSaidWhenTheStoredRoleAgrees(): void
    {
        $this->role('owner', ['write', 'comment'], system: true);

        $this->assertSame([], $this->drift(['owner' => ['write', 'comment']]));
    }

    /**
     * An installation that added something of its own has not drifted.
     *
     * Only what the declaration names is asked for. Reporting the other
     * direction would tell an installation off for its own decisions.
     */
    public function testExtraPermissionsOnAStoredRoleAreItsOwnBusiness(): void
    {
        $this->role('owner', ['write', 'comment', 'something.local'], system: true);

        $this->assertSame([], $this->drift(['owner' => ['write']]));
    }

    /**
     * A declared role that was never written is the other command's job.
     *
     * syncDeclared creates it, with everything it declares. Counting it here
     * would report drift on a role that is about to be correct.
     */
    public function testARoleThatDoesNotExistYetIsNotDrift(): void
    {
        $this->assertSame([], $this->drift(['nobody-wrote-me' => ['write']]));
    }

    /**
     * Several roles, and each only against its own declaration.
     */
    public function testEachRoleIsComparedWithItsOwn(): void
    {
        $this->role('owner', ['write'], system: true);
        $this->role('manager', ['write', 'comment'], system: true);

        $this->assertSame(
            ['owner' => ['delete'], 'manager' => ['export']],
            $this->drift([
                'owner'   => ['write', 'delete'],
                'manager' => ['write', 'comment', 'export'],
            ]),
        );
    }

    /**
     * @param array<string, list<string>> $declared Role key to the permissions it declares
     *
     * @return array<string, list<string>>
     */
    private function drift(array $declared): array
    {
        $definitions = [];
        foreach ($declared as $name => $permissions) {
            $definitions[$name] = new RoleDefinition($name, ucfirst($name), '', $permissions);
        }

        return $this->roles->declaredDrift($definitions, $this->registry);
    }
}
