<?php

declare(strict_types=1);

namespace Naf\Rbac\Service;

use Naf\Rbac\Events\GrantsChanged;
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
     *
     * @return list<GrantsChanged> what actually moved, for a caller that keeps a
     *                             history. Returned rather than announced: this
     *                             package has no opinion about histories, and a
     *                             service that reaches for an event dispatcher
     *                             needs a booted application to be used at all.
     */
    public function apply(int $actorId, int $targetId, array $wanted): array
    {
        /** @var array<string, list<int>> $byPlace */
        $byPlace = [];
        foreach ($wanted as $grant) {
            $byPlace[$grant['scope']][] = $grant['role'];
        }

        // Every place they hold something in today, so a removal is a removal --
        // and what they held there, so what happened can be told afterwards.
        $held = [];
        foreach ($this->assignments->grantsOf($targetId) as $existing) {
            $byPlace[$existing['scope']] ??= [];
            $held[$existing['scope']][$existing['role_id']] = $existing['label'];
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

        return $this->moved($actorId, $targetId, $byPlace, $held);
    }

    /**
     * What moved, once per place, and only where something did.
     *
     * Worked out after the write and returned rather than dispatched: a caller
     * that has committed can say something happened, and one that rolled back
     * never gets this far.
     *
     * @param array<string, list<int>>          $byPlace what they are to hold, per place
     * @param array<string, array<int, string>> $held    what they held, per place
     *
     * @return list<GrantsChanged>
     */
    private function moved(int $actorId, int $targetId, array $byPlace, array $held): array
    {
        $labels = $this->labels($byPlace);
        $moved  = [];

        foreach ($byPlace as $scope => $roleIds) {
            $change = new GrantsChanged(
                $actorId,
                $targetId,
                (string) $scope,
                array_values($held[$scope] ?? []),
                array_values(array_filter(array_map(
                    static fn(int $role): ?string => $labels[$role] ?? null,
                    array_unique($roleIds),
                ))),
            );

            if (!$change->isNothing()) {
                $moved[] = $change;
            }
        }

        return $moved;
    }

    /**
     * The labels of every role about to be granted, read once.
     *
     * By label rather than by id, because a log has to stay readable after the
     * role it names has been renamed or deleted.
     *
     * @param array<string, list<int>> $byPlace
     *
     * @return array<int, string>
     */
    private function labels(array $byPlace): array
    {
        $ids = array_values(array_unique(array_merge(...array_values($byPlace)) ?: []));
        if ($ids === []) {
            return [];
        }

        $statement = $this->connection->prepare(
            'SELECT id, label FROM rbac_roles WHERE id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')',
        );
        $statement->execute($ids);

        return array_column($statement->fetchAll(PDO::FETCH_ASSOC), 'label', 'id');
    }
}
