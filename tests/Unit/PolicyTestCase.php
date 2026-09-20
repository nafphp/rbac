<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Rbac\Exceptions\PrivilegedActionDenied;
use Naf\Rbac\Migrations\M202609200001Rbac;
use Naf\Rbac\Policy\PrivilegePolicy;
use Naf\Rbac\Registry\PermissionRegistry;
use Naf\Rbac\Repository\AssignmentRepository;
use Naf\Rbac\Repository\RoleRepository;
use Naf\Rbac\Scope;
use PDO;
use PHPUnit\Framework\TestCase;

/** An installation in memory: a few roles, a few people holding them. */
abstract class PolicyTestCase extends TestCase
{
    protected const string LOCKOUT = 'rbac.manage';

    protected PDO $connection;
    protected PermissionRegistry $permissions;
    protected RoleRepository $roles;
    protected AssignmentRepository $assignments;
    protected PrivilegePolicy $policy;

    protected function setUp(): void
    {
        $this->connection = new PDO('sqlite::memory:', options: [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        (new M202609200001Rbac())->up($this->connection);

        $this->permissions = new PermissionRegistry();
        $this->roles       = new RoleRepository($this->connection);
        $this->assignments = new AssignmentRepository($this->connection, $this->permissions);
        $this->policy      = new PrivilegePolicy($this->roles, $this->assignments, self::LOCKOUT);
    }

    /** @param list<string> $permissions */
    protected function role(
        string $name,
        array $permissions,
        bool $system = false,
        string $scopeType = '',
    ): int {
        return $this->roles->create($name, ucfirst($name), '', $permissions, $scopeType, $system);
    }

    /** @param list<int> $roleIds */
    protected function person(int $id, array $roleIds, ?Scope $at = null): int
    {
        $this->assignments->assign($id, $roleIds, $at);

        return $id;
    }

    /** Assert the action is refused, and for the stated reason. */
    protected function assertDenied(string $reason, callable $action): void
    {
        try {
            $action();
        } catch (PrivilegedActionDenied $denied) {
            self::assertSame($reason, $denied->reason, $denied->getMessage());

            return;
        }

        self::fail(sprintf('Expected the action to be denied as "%s", but it was allowed.', $reason));
    }
}
