<?php

declare(strict_types=1);

return ['rbac' => [
    /*
     * The permission nobody may be the last to lose.
     *
     * Every rule about administrators reduces to this one: an installation must
     * keep at least one account that can still hand out roles. Naming it as a
     * permission rather than as a role means a host is free to call its top role
     * whatever it likes, and to have several that qualify.
     */
    'lockout_permission' => 'rbac.manage',

    /*
     * Where the management pages live, or null to register no routes at all --
     * for a host that would rather build its own screens on the same services.
     */
    'path' => '/admin/roles',

    /*
     * The layout the shipped views extend. Left at null they render bare, which
     * is right for a host that includes them in a page of its own.
     */
    'layout' => null,
]];
