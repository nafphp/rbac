<?php

declare(strict_types=1);

namespace Naf\Rbac\Repository;

use Naf\Rbac\Permissions\Everything;
use Naf\Rbac\Registry\PermissionRegistry;
use Naf\Rbac\Scope;
use PDO;

/**
 * Who holds which role where, and what that adds up to in a given place.
 *
 * Every read takes the place it is asking about. `permissionsOf` runs for every
 * check a signed-in person makes, so it is one query and the caller caches.
 */
final readonly class AssignmentRepository
{
    public function __construct(
        private PDO $connection,
        private PermissionRegistry $permissions,
    ) {
    }

    /** @return list<string> role names held in $at, sorted */
    public function rolesOf(int $userId, ?Scope $at = null): array
    {
        [$clause, $parameters] = $this->covering($at);

        $statement = $this->connection->prepare(
            'SELECT DISTINCT r.name FROM rbac_user_roles ur JOIN rbac_roles r ON r.id = ur.role_id'
            . " WHERE ur.user_id = ? AND $clause ORDER BY r.name",
        );
        $statement->execute([$userId, ...$parameters]);

        return array_map(strval(...), $statement->fetchAll(PDO::FETCH_COLUMN));
    }

    /** @return list<string> permissions that have effect in $at, sorted, without duplicates */
    public function permissionsOf(int $userId, ?Scope $at = null): array
    {
        [$clause, $parameters] = $this->covering($at);

        $statement = $this->connection->prepare(
            'SELECT DISTINCT rp.permission FROM rbac_user_roles ur'
            . ' JOIN rbac_role_permissions rp ON rp.role_id = ur.role_id'
            . " WHERE ur.user_id = ? AND $clause ORDER BY rp.permission",
        );
        $statement->execute([$userId, ...$parameters]);
        $stored = array_map(strval(...), $statement->fetchAll(PDO::FETCH_COLUMN));

        return in_array(Everything::KEY, $stored, true) ? $this->andEverythingElse($stored) : $stored;
    }

    /**
     * What `rbac.all` adds up to, resolved here rather than stored.
     *
     * Every read goes through this method -- the policy asks it directly, not
     * only through the cache in Rbac -- so expanding here is what keeps the
     * answer the same everywhere. A grant that is still in the table but whose
     * package is gone stays in the list, exactly as it would without this.
     *
     * `holdersOfPermission` counts stored rows and does not see this expansion.
     * That is on purpose: the lockout guard may undercount keepers and refuse,
     * never overcount and let the last one go.
     *
     * @param  list<string> $stored
     * @return list<string>
     */
    private function andEverythingElse(array $stored): array
    {
        $all = array_values(array_unique([...$stored, ...array_keys($this->permissions->all())]));
        sort($all);

        return $all;
    }

    /**
     * Every grant somebody holds, for the screen that edits them.
     *
     * @return list<array{role_id:int,role:string,label:string,scope:string}>
     */
    public function grantsOf(int $userId): array
    {
        $statement = $this->connection->prepare(
            'SELECT ur.role_id, r.name AS role, r.label, ur.scope'
            . ' FROM rbac_user_roles ur JOIN rbac_roles r ON r.id = ur.role_id'
            . ' WHERE ur.user_id = ? ORDER BY ur.scope, r.position, r.name',
        );
        $statement->execute([$userId]);

        return array_map(
            static fn(array $row) => [
                'role_id' => (int) $row['role_id'],
                'role'    => (string) $row['role'],
                'label'   => (string) $row['label'],
                'scope'   => (string) $row['scope'],
            ],
            $statement->fetchAll(PDO::FETCH_ASSOC),
        );
    }

    /**
     * How many accounts hold a permission that has effect in $at.
     *
     * The lockout guard asks this before it lets the last one go. It counts
     * people, not grants: holding the same thing twice is still one person who
     * could undo the change.
     */
    public function holdersOfPermission(string $permission, ?Scope $at = null): int
    {
        [$clause, $parameters] = $this->covering($at);

        $statement = $this->connection->prepare(
            'SELECT COUNT(DISTINCT ur.user_id) FROM rbac_user_roles ur'
            . ' JOIN rbac_role_permissions rp ON rp.role_id = ur.role_id'
            . " WHERE rp.permission = ? AND $clause",
        );
        $statement->execute([$permission, ...$parameters]);

        return (int) $statement->fetchColumn();
    }

    /** @return list<int> user ids holding the role anywhere */
    public function holdersOf(string $role): array
    {
        $statement = $this->connection->prepare(
            'SELECT DISTINCT ur.user_id FROM rbac_user_roles ur JOIN rbac_roles r ON r.id = ur.role_id'
            . ' WHERE r.name = ?',
        );
        $statement->execute([$role]);

        return array_map(intval(...), $statement->fetchAll(PDO::FETCH_COLUMN));
    }

    /**
     * Replace somebody's roles in one place, leaving every other place alone.
     *
     * Scoped on purpose: taking a person off one board must not quietly take
     * them off the others, and the screen that edits one board only knows about
     * that one.
     *
     * @param list<int> $roleIds
     */
    public function assign(int $userId, array $roleIds, ?Scope $at = null, ?int $grantedBy = null): void
    {
        $scope = (string) ($at ?? Scope::everywhere());

        $this->connection
            ->prepare('DELETE FROM rbac_user_roles WHERE user_id = ? AND scope = ?')
            ->execute([$userId, $scope]);

        $insert = $this->connection->prepare(
            'INSERT INTO rbac_user_roles(user_id,role_id,scope,granted_by) VALUES(?,?,?,?)',
        );
        foreach (array_unique($roleIds) as $roleId) {
            $insert->execute([$userId, $roleId, $scope, $grantedBy]);
        }
    }

    /**
     * The WHERE fragment that keeps only the grants having effect in $at.
     *
     * Three spellings can reach a place -- everywhere, every instance of its
     * kind, and that instance -- which is Scope::covers() expressed as equality
     * so an index can serve it. The two stay in step because both are derived
     * from the same value.
     *
     * @return array{string, list<string>}
     */
    private function covering(?Scope $at): array
    {
        $at    = $at ?? Scope::everywhere();
        $exact = (string) $at;
        $kind  = $at->isEverywhere() ? '' : $at->type . ':*';

        return ['(ur.scope = ? OR ur.scope = ? OR ur.scope = ?)', ['', $exact, $kind]];
    }
}
