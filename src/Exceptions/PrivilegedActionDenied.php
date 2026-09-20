<?php

declare(strict_types=1);

namespace Naf\Rbac\Exceptions;

use RuntimeException;

/**
 * A role or assignment change the actor is not allowed to make.
 *
 * The reason is a stable key for logs and tests; the message is for the person
 * who tried. Both are deliberate: a denial that only says "forbidden" teaches
 * whoever hits it nothing, and one that explains itself in prose cannot be
 * asserted on.
 */
final class PrivilegedActionDenied extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
