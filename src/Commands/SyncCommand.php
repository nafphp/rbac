<?php

declare(strict_types=1);

namespace Naf\Rbac\Commands;

use Naf\CLI\Core\AbstractCommand;
use Naf\CLI\Core\Input;
use Naf\CLI\Core\Output;

use function Naf\Rbac\rbac;

/**
 * Write the roles the installed packages declare.
 *
 * Run after migrating. It adds what is missing and leaves alone what is there:
 * the permission list on a declaration is where a role starts, not a standing
 * instruction, so an installation that took a permission away from its own
 * editor role keeps that decision across upgrades.
 *
 * @internal
 */
final class SyncCommand extends AbstractCommand
{
    public const string NAME = 'rbac:sync';

    protected function configure(): void
    {
        $this
            ->setTitle('Sync declared roles')
            ->setDescription('Write the roles installed packages declare, without overwriting local changes.')
            ->addOption('reapply');
    }

    public function run(Input $input, Output $output): int
    {
        $rbac     = rbac();
        $declared = $rbac->declared->all();
        $before   = array_column($rbac->roles->all(), 'name');

        $reapply = $input->getOption('reapply') === true;
        $rbac->roles->syncDeclared($declared, $rbac->declared, $reapply);

        $added = array_diff(array_keys($declared), $before);
        $output->writeLine(sprintf(
            '%d declared role(s); %s',
            count($declared),
            $added === [] ? 'nothing to add' : 'added ' . implode(', ', $added),
        ), 'success');

        $output->writeLine(sprintf(
            '%d permission(s) declared across %d group(s).',
            count($rbac->permissions->all()),
            count($rbac->permissions->grouped()),
        ));

        if ($reapply) {
            $output->writeLine(
                'Declared roles were reset to the permissions their packages name. Anything this '
                . 'installation had changed about them is gone.',
                'warning',
            );

            return self::SUCCESS;
        }

        foreach ($rbac->roles->declaredDrift($declared, $rbac->declared) as $role => $missing) {
            $output->writeLine(sprintf('  %s is missing %s', $role, implode(', ', $missing)), 'warning');
            $drifted = true;
        }

        if ($drifted ?? false) {
            $output->writeLine(
                'The roles above no longer carry everything their packages declare. That is kept on '
                . 'purpose, in case this installation meant it -- but a permission added by an '
                . 'upgrade reaches nobody this way, and the feature behind it will look broken. '
                . 'Grant it in the role editor, or run this command with --reapply to take the '
                . "packages' word for all of them.",
                'warning',
            );
        }

        return self::SUCCESS;
    }
}
