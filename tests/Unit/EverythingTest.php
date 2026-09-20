<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Rbac\Definition\PermissionDefinition;
use Naf\Rbac\Permissions\Everything;
use Naf\Rbac\Scope;

/**
 * The permission that carries the rest.
 *
 * An administrator's list cannot be kept current by hand, because a package
 * declares permissions after the grant was written. Resolving `rbac.all` when
 * it is read, rather than writing the list onto the role, is what makes
 * "may do everything" stay true as the installation grows.
 */
final class EverythingTest extends PolicyTestCase
{
    public function testItCarriesPermissionsItWasNeverGranted(): void
    {
        $this->permissions->add(new PermissionDefinition('posts.publish', 'Publish', '', 'Posts', 10));
        $admin = $this->role('admin', [Everything::KEY]);
        $this->person(1, [$admin]);

        $this->assertContains('posts.publish', $this->assignments->permissionsOf(1));
    }

    public function testAPermissionDeclaredAfterTheGrantIsCarriedToo(): void
    {
        $admin = $this->role('admin', [Everything::KEY]);
        $this->person(1, [$admin]);
        $this->assertNotContains('posts.publish', $this->assignments->permissionsOf(1));

        // The package arrives later, which is the whole point: nobody re-grants
        // anything, and the administrator may use it.
        $this->permissions->add(new PermissionDefinition('posts.publish', 'Publish', '', 'Posts', 10));

        $this->assertContains('posts.publish', $this->assignments->permissionsOf(1));
    }

    public function testItReachesIntoAScopeTheGrantDoesNotName(): void
    {
        $this->permissions->add(new PermissionDefinition('write', 'Write', '', 'Board', 10));
        $admin = $this->role('admin', [Everything::KEY]);
        $this->person(1, [$admin]);

        // Held for the whole installation, so it counts inside a board as well.
        // This is what let the role editor lock every project role: the actor's
        // installation-wide list never contained a board permission.
        $this->assertContains('write', $this->assignments->permissionsOf(1, Scope::of('project', '7')));
    }

    public function testSomebodyWithoutItKeepsExactlyWhatWasGranted(): void
    {
        $this->permissions->add(new PermissionDefinition('posts.publish', 'Publish', '', 'Posts', 10));
        $member = $this->role('member', ['write']);
        $this->person(2, [$member]);

        $this->assertSame(['write'], $this->assignments->permissionsOf(2));
    }

    public function testAGrantWhosePackageIsGoneIsStillNotInterpreted(): void
    {
        $admin = $this->role('admin', [Everything::KEY, 'orphan.left.behind']);
        $this->person(1, [$admin]);

        // It stays in the list because it is stored, exactly as it would without
        // rbac.all. Whether anything answers to that name is not this layer's
        // question.
        $this->assertContains('orphan.left.behind', $this->assignments->permissionsOf(1));
    }
}
