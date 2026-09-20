<?php

declare(strict_types=1);

namespace Naf\Rbac\Contracts;

/**
 * Where a host's places come from.
 *
 * This package knows that a grant can be attached to something, and nothing at
 * all about what that something is. A host registers one of these per kind, and
 * the screens can then offer "on which boards" without ever learning what a
 * board is. A second kind -- teams, tenants, sites -- is another registration
 * and no change here.
 */
interface ScopeSourceInterface
{
    /** The kind, as it appears in a scope: "project" in project:7. */
    public function type(): string;

    /** Plural, for the heading above the list: "Boards". */
    public function label(): string;

    /**
     * What may be granted on, as id => label.
     *
     * Called when a screen is rendered, so it may be narrowed to what the person
     * doing the granting can see. Returning nothing hides the kind entirely.
     *
     * @return array<string, string>
     */
    public function instances(): array;
}
