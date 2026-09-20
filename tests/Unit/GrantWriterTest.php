<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Rbac\Exceptions\PrivilegedActionDenied;
use Naf\Rbac\Scope;
use Naf\Rbac\Service\GrantWriter;

/** Editing one person across every place at once. */
final class GrantWriterTest extends PolicyTestCase
{
    private GrantWriter $writer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->writer = new GrantWriter($this->connection, $this->assignments, $this->policy);
    }

    public function testItGrantsDifferentRolesInDifferentPlaces(): void
    {
        $admin      = $this->role('admin', [self::LOCKOUT, 'board.settings', 'tickets.write']);
        $maintainer = $this->role('maintainer', ['board.settings', 'tickets.write'], scopeType: 'project');
        $member     = $this->role('member', ['tickets.write'], scopeType: 'project');
        $actor      = $this->person(1, [$admin]);

        $this->writer->apply($actor, 7, [
            ['role' => $maintainer, 'scope' => 'project:1'],
            ['role' => $member,     'scope' => 'project:2'],
        ]);

        self::assertSame(['maintainer'], $this->assignments->rolesOf(7, Scope::of('project', 1)));
        self::assertSame(['member'], $this->assignments->rolesOf(7, Scope::of('project', 2)));
    }

    /**
     * The row that is no longer on the form is the removal, and it has to reach
     * the database -- otherwise the screen and the grants quietly disagree.
     */
    public function testAPlaceLeftOutOfTheFormIsCleared(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, 'tickets.write']);
        $member = $this->role('member', ['tickets.write'], scopeType: 'project');
        $actor  = $this->person(1, [$admin]);

        $this->writer->apply($actor, 7, [
            ['role' => $member, 'scope' => 'project:1'],
            ['role' => $member, 'scope' => 'project:2'],
        ]);
        self::assertSame(['member'], $this->assignments->rolesOf(7, Scope::of('project', 2)));

        $this->writer->apply($actor, 7, [['role' => $member, 'scope' => 'project:1']]);

        self::assertSame([], $this->assignments->rolesOf(7, Scope::of('project', 2)));
        self::assertSame(['member'], $this->assignments->rolesOf(7, Scope::of('project', 1)));
    }

    public function testNothingIsWrittenWhenOnePlaceIsRefused(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, 'tickets.write']);
        $member = $this->role('member', ['tickets.write'], scopeType: 'project');
        $actor  = $this->person(1, [$admin]);

        // The second grant names a board role at the installation level, which
        // the policy refuses -- and the first must not survive it.
        try {
            $this->writer->apply($actor, 7, [
                ['role' => $member, 'scope' => 'project:1'],
                ['role' => $member, 'scope' => ''],
            ]);
            self::fail('The whole change should have been refused.');
        } catch (PrivilegedActionDenied $denied) {
            self::assertSame('role_not_grantable_here', $denied->reason);
        }

        self::assertSame(
            [],
            $this->assignments->rolesOf(7, Scope::of('project', 1)),
            'a refused change was applied in part',
        );
    }

    public function testTakingEverythingAwayIsAnEmptyList(): void
    {
        $admin  = $this->role('admin', [self::LOCKOUT, 'tickets.write']);
        $member = $this->role('member', ['tickets.write'], scopeType: 'project');
        $actor  = $this->person(1, [$admin]);

        $this->writer->apply($actor, 7, [['role' => $member, 'scope' => 'project:1']]);
        $this->writer->apply($actor, 7, []);

        self::assertSame([], $this->assignments->grantsOf(7));
    }
}
