<?php

declare(strict_types=1);

namespace Naf\Rbac\Repository;

use Naf\Rbac\Contracts\RoleInterface;
use Naf\Rbac\Registry\RoleRegistry;
use PDO;

/**
 * The roles themselves, and the permissions each one carries.
 *
 * Nothing here asks whether the caller may do it. That question belongs to
 * PrivilegePolicy, which every write goes through first -- keeping the two
 * apart is what lets the policy be read as a list of rules rather than being
 * scattered through SQL.
 */
final readonly class RoleRepository
{
    public function __construct(private PDO $connection)
    {
    }

    /** @return list<array{id:int,name:string,label:string,description:string,scopeType:string,system:bool,position:int,version:int,permissions:list<string>,holders:int}> */
    public function all(): array
    {
        $roles = $this->connection->query(
            'SELECT r.*, (SELECT COUNT(*) FROM rbac_user_roles ur WHERE ur.role_id = r.id) AS holders'
            . ' FROM rbac_roles r ORDER BY r.position, r.name',
        )->fetchAll(PDO::FETCH_ASSOC);

        $granted = [];
        foreach (
            $this->connection->query(
                'SELECT role_id, permission FROM rbac_role_permissions ORDER BY permission',
            ) as $row
        ) {
            $granted[(int) $row['role_id']][] = (string) $row['permission'];
        }

        return array_map(
            static fn(array $role) => [
                'id'          => (int) $role['id'],
                'name'        => (string) $role['name'],
                'scopeType'   => (string) $role['scope_type'],
                'label'       => (string) $role['label'],
                'description' => (string) $role['description'],
                'system'      => (int) $role['system'] === 1,
                'position'    => (int) $role['position'],
                'version'     => (int) $role['version'],
                'holders'     => (int) $role['holders'],
                'permissions' => $granted[(int) $role['id']] ?? [],
            ],
            $roles,
        );
    }

    /** @return array{id:int,name:string,label:string,description:string,scopeType:string,system:bool,position:int,version:int,permissions:list<string>,holders:int}|null */
    public function find(int $id): ?array
    {
        foreach ($this->all() as $role) {
            if ($role['id'] === $id) {
                return $role;
            }
        }

        return null;
    }

    public function idOf(string $name): ?int
    {
        $statement = $this->connection->prepare('SELECT id FROM rbac_roles WHERE name = ?');
        $statement->execute([$name]);
        $id = $statement->fetchColumn();

        return $id === false ? null : (int) $id;
    }

    /** @param list<string> $permissions */
    public function create(
        string $name,
        string $label,
        string $description,
        array $permissions,
        string $scopeType = '',
        bool $system = false,
        int $position = 100,
    ): int {
        $this->connection
            ->prepare(
                'INSERT INTO rbac_roles(name,scope_type,label,description,system,position)'
                . ' VALUES(?,?,?,?,?,?)',
            )
            ->execute([$name, $scopeType, $label, $description, $system ? 1 : 0, $position]);

        $id = (int) $this->connection->lastInsertId();
        $this->setPermissions($id, $permissions);

        return $id;
    }

    /** @param list<string> $permissions */
    public function update(int $id, string $label, string $description, array $permissions): void
    {
        $this->connection
            ->prepare(
                'UPDATE rbac_roles SET label = ?, description = ?, version = version + 1 WHERE id = ?',
            )
            ->execute([$label, $description, $id]);

        $this->setPermissions($id, $permissions);
    }

    public function delete(int $id): void
    {
        $this->connection->prepare('DELETE FROM rbac_roles WHERE id = ? AND system = 0')->execute([$id]);
    }

    /**
     * Write the roles a host declares, without touching what an installation decided.
     *
     * A declared role that is already there keeps its permissions: the list on
     * the definition is the starting point, not a standing instruction. That is
     * what keeps installing a package from widening anybody's access.
     *
     * It also means a permission declared later never reaches an existing role,
     * and since nobody may grant what nobody holds, such a permission would be
     * unreachable forever. `$reapply` is the way out, and it is deliberately an
     * argument rather than the default: re-applying a declaration throws away
     * whatever the installation decided about those roles, so it is somebody's
     * decision and not a side effect of an upgrade.
     *
     * @param array<string, RoleInterface> $definitions
     */
    public function syncDeclared(array $definitions, RoleRegistry $registry, bool $reapply = false): void
    {
        foreach ($definitions as $definition) {
            $id = $this->idOf($definition->getKey());
            if ($id === null) {
                $this->create(
                    $definition->getKey(),
                    $definition->getLabel(),
                    $definition->getDescription(),
                    $registry->permissionsOf($definition),
                    $definition->getScopeType(),
                    true,
                    $definition->getOrder(),
                );

                continue;
            }

            // Declared roles stay declared, so the rules may keep naming them.
            $this->connection
                ->prepare('UPDATE rbac_roles SET system = 1 WHERE id = ?')
                ->execute([$id]);

            if ($reapply) {
                $this->setPermissions($id, $registry->permissionsOf($definition));
            }
        }
    }

    /** @param list<string> $permissions */
    private function setPermissions(int $id, array $permissions): void
    {
        $this->connection->prepare('DELETE FROM rbac_role_permissions WHERE role_id = ?')->execute([$id]);

        $insert = $this->connection->prepare(
            'INSERT INTO rbac_role_permissions(role_id,permission) VALUES(?,?)',
        );
        foreach (array_unique($permissions) as $permission) {
            $insert->execute([$id, $permission]);
        }
    }
}
