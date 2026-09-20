<?php

declare(strict_types=1);

namespace Naf\Rbac\Events;

/**
 * Somebody's roles in one place are now these, and were those.
 *
 * Dispatched as `rbac.granted`, once per place that changed. What a host does
 * with it is the host's business -- this package keeps no history of its own,
 * because a history is a product decision and access control is not.
 *
 * The roles travel by label and not by id. An id in a record is a promise that
 * the row behind it still exists and still means the same thing, and a log has
 * to be readable after the role it names has been renamed or deleted.
 */
final readonly class GrantsChanged
{
    /**
     * @param string       $scope  where this applies, as stored: `project:7`, or empty
     * @param list<string> $before what they held there until now
     * @param list<string> $after  what they hold there from now on
     */
    public function __construct(
        public int $actorId,
        public int $targetId,
        public string $scope,
        public array $before,
        public array $after,
    ) {
    }

    /** Nothing actually moved: the same labels, in whatever order they arrived. */
    public function isNothing(): bool
    {
        $before = $this->before;
        $after  = $this->after;
        sort($before);
        sort($after);

        return $before === $after;
    }
}
