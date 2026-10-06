<?php

declare(strict_types=1);

namespace Tests\Integration;

use Naf\Rbac\Definition\RoleDefinition;
use Naf\Rbac\Migrations\M202609200001Rbac;
use Naf\Rbac\Registry\PermissionRegistry;
use Naf\Rbac\Registry\RoleRegistry;
use Naf\Rbac\Repository\RoleRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class MySqlRoleTest extends TestCase
{
    public function testMigrationAndDeclaredRoleWritesOnMySql(): void
    {
        $dsn = getenv('NAF_RBAC_MYSQL_DSN');
        if (!$dsn) {
            $this->markTestSkipped('Set NAF_RBAC_MYSQL_DSN for the isolated MySQL acceptance.');
        }

        $connection = new PDO($dsn, getenv('NAF_RBAC_MYSQL_USER') ?: 'board', getenv('NAF_RBAC_MYSQL_PASSWORD') ?: 'board');
        self::assertSame('nafinity_rbac_test', $connection->query('SELECT DATABASE()')->fetchColumn());
        $migration = new M202609200001Rbac();
        $migration->down($connection);

        try {
            $migration->up($connection);
            $roles    = new RoleRepository($connection);
            $declared = $roles->create('owner', 'Owner', '', ['write'], system: true);
            $custom   = $roles->create('editor', 'Editor', '', ['read']);
            self::assertTrue($roles->find($declared)['system']);
            self::assertFalse($roles->find($custom)['system']);

            $roles->delete($declared);
            self::assertNotNull($roles->find($declared));
            $roles->delete($custom);
            self::assertNull($roles->find($custom));

            $registry = new RoleRegistry(new PermissionRegistry());
            $role     = new RoleDefinition('owner', 'Owner', '', ['write']);
            $registry->add($role);
            $roles->syncDeclared(['owner' => $role], $registry);
            self::assertTrue($roles->find($declared)['system']);
            self::assertSame(['write'], $roles->find($declared)['permissions']);
        } finally {
            $migration->down($connection);
        }

        self::assertSame([], $connection->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN));
    }
}
