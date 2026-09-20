<?php

declare(strict_types=1);

namespace Naf\Rbac\Migrations;

use Naf\Database\Core\AbstractMigration;
use PDO;

/**
 * Roles, the permissions they carry, and who holds them.
 *
 * There is no table of permissions. The vocabulary is declared in code, so the
 * registry already is the truth about it and a copy here could only go stale --
 * a package uninstalled for an afternoon would leave rows claiming otherwise.
 * What is stored is the grants, and a grant outlives the package that declared
 * it: the permission comes back when the package does, rather than the role
 * having been quietly rewritten in the meantime.
 *
 * @internal
 */
final class M202609200001Rbac extends AbstractMigration
{
    public function up(PDO $connection): void
    {
        // All three, because a reusable package does not get to assume the host's
        // database. SQLite only counts up on its own for INTEGER PRIMARY KEY.
        $id = match ($connection->getAttribute(PDO::ATTR_DRIVER_NAME)) {
            'mysql'  => 'BIGINT AUTO_INCREMENT PRIMARY KEY',
            'sqlite' => 'INTEGER PRIMARY KEY AUTOINCREMENT',
            default  => 'BIGSERIAL PRIMARY KEY',
        };

        $tables = [
            // `system` marks the roles a host declares in code. They may gain and
            // lose permissions, but they cannot be renamed away or deleted, so
            // the rules that name a role by its key keep meaning something.
            //
            // `scope_type` is where a role may be handed out: empty for one that
            // only means anything installation-wide, or the kind of thing it
            // attaches to -- "project" for a role somebody holds on one board and
            // not on the next. A role belongs to exactly one of these, because a
            // role that means different things in different places is two roles.
            'rbac_roles' => "id $id,"
                . 'name VARCHAR(80) NOT NULL UNIQUE,'
                . 'scope_type VARCHAR(40) NOT NULL DEFAULT \'\','
                . 'label VARCHAR(120) NOT NULL,'
                . 'description VARCHAR(255) NOT NULL DEFAULT \'\','
                . 'system SMALLINT NOT NULL DEFAULT 0,'
                . 'position BIGINT NOT NULL DEFAULT 100,'
                . 'version BIGINT NOT NULL DEFAULT 1,'
                . 'created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP',

            // The permission is a plain string, not a reference: a grant outlives
            // the package that declared it and comes back when the package does.
            'rbac_role_permissions' => 'role_id BIGINT NOT NULL,'
                . 'permission VARCHAR(120) NOT NULL,'
                . 'PRIMARY KEY(role_id,permission),'
                . 'FOREIGN KEY(role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE',

            /*
             * One grant is a person, a role, and where it applies:
             *
             *   ''            everywhere
             *   project:7     on that board
             *   project:*     on every board of that kind
             *
             * The place is part of the key, so the same role may be held in
             * several and the pair (person, role) is no longer unique. That is
             * the whole of the tenancy: one column, and every rule below asks
             * its questions with it.
             */
            'rbac_user_roles' => 'user_id BIGINT NOT NULL,'
                . 'role_id BIGINT NOT NULL,'
                . 'scope VARCHAR(80) NOT NULL DEFAULT \'\','
                . 'granted_by BIGINT NULL,'
                . 'granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,'
                . 'PRIMARY KEY(user_id,role_id,scope),'
                . 'FOREIGN KEY(role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE',
        ];

        foreach ($tables as $table => $definition) {
            $connection->exec("CREATE TABLE IF NOT EXISTS $table ($definition)");
        }
    }

    public function down(PDO $connection): void
    {
        foreach (
            ['rbac_user_roles', 'rbac_role_permissions', 'rbac_roles'] as $table
        ) {
            $connection->exec("DROP TABLE IF EXISTS $table");
        }
    }
}
