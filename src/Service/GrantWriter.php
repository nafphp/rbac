<?php

declare(strict_types=1);

namespace Naf\Rbac\Service;

use Naf\Rbac\Policy\PrivilegePolicy;
use Naf\Rbac\Repository\AssignmentRepository;
use Naf\Rbac\Scope;
use PDO;
use Throwable;

/**
 * One person's grants, as a whole.
 *
 * The screen that edits somebody shows every place at once, so it submits every
 * place at once, and two things follow that are easy to get wrong:
 *
 * A place the person holds something in today but that the form no longer
 * mentions has to be **cleared**. Without that, taking somebody off a board by
 * removing its row would leave the grant sitting there, and the screen would
 * keep agreeing with itself while the database disagreed.
 *
 * And every place is checked before any place is written. A refusal halfway
 * through would leave somebody with the roles from the first three boards and
 * not the rest -- a state nobody asked for and no screen would show.
 */
final readonly class GrantWriter
{
    public function __construct(
        private PDO $connection,
        private AssignmentRepository $assignments,
        private PrivilegePolicy $policy,
    ) {
    }

    /**
     * @param list<array{role:int,scope:string}> $wanted what the person is to hold afterwards
     */
    public function apply(int $actorId, int $targetId, array $wanted): void
    {
        /** @var array<string, list<int>> $byPlace */
        $byPlace = [];
        foreach ($wanted as $grant) {
            $byPlace[$grant['scope']][] = $grant['role'];
        }

        // Every place they hold something in today, so a removal is a removal.
        foreach ($this->assignments->grantsOf($targetId) as $existing) {
            $byPlace[$existing['scope']] ??= [];
        }

        foreach ($byPlace as $scope => $roleIds) {
            $this->policy->assertAssignment(
                $actorId,
                $targetId,
                array_values(array_unique($roleIds)),
                Scope::parse((string) $scope),
            );
        }

        // A host may already have one open; starting a second is an error rather
        // than a nested transaction, and this is not the layer to decide that.
        $owned = !$this->connection->inTransaction();
        if ($owned) {
            $this->connection->beginTransaction();
        }

        try {
            foreach ($byPlace as $scope => $roleIds) {
                $this->assignments->assign(
                    $targetId,
                    array_values(array_unique($roleIds)),
                    Scope::parse((string) $scope),
                    $actorId,
                );
            }
        } catch (Throwable $failure) {
            if ($owned) {
                $this->connection->rollBack();
            }

            throw $failure;
        }

        if ($owned) {
            $this->connection->commit();
        }
    }
}
