<?php

declare(strict_types=1);

/**
 * The rules are the thing worth testing, and they need no host.
 *
 * PrivilegePolicy asks two repositories questions and answers with a yes or a
 * throw; all three want a PDO and nothing else. So the suite runs against an
 * in-memory SQLite with this package's own migration applied, and boots no
 * application at all -- which is also why every rule below can be written as
 * one arrangement and one assertion.
 *
 * The one thing borrowed from outside is AbstractMigration. NAF_HOST points at
 * an installation that has it; the fallback is the installed layout,
 * <host>/vendor/naf/rbac/tests.
 */

$host = getenv('NAF_HOST') ?: dirname(__DIR__, 4);

if (!is_file($host . '/vendor/autoload.php')) {
    fwrite(STDERR, "No host application at $host. Set NAF_HOST to an installation that has naf/database.\n");
    exit(2);
}

require_once $host . '/vendor/autoload.php';

// Prepended, because a host may also have an installed copy of this package and
// the working copy under test has to win.
spl_autoload_register(static function (string $class): void {
    foreach (['Naf\\Rbac\\' => __DIR__ . '/../src/', 'Tests\\' => __DIR__ . '/'] as $prefix => $base) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }

        $file = $base . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require_once $file;
        }
    }
}, prepend: true);
