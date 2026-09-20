<?php

declare(strict_types=1);

namespace Naf\Rbac\Identity;

use Naf\Auth\Identity\UserInterface;

/**
 * A user model whose roles and permissions come from here.
 *
 * It adds nothing to `Naf\Auth\Identity\UserInterface`, and that is the point:
 * a model already answering that contract becomes governed by this package by
 * saying so, and everything downstream -- `auth()->can()`, `requirePermission()`
 * -- keeps working because the contract it speaks has not changed.
 *
 * Pair it with the ResolvesGrants trait, which is the whole implementation:
 *
 *     final class User extends AbstractModel implements GrantedInterface
 *     {
 *         use ResolvesGrants;
 *     }
 *
 * Declaring it without the trait is allowed and occasionally right -- a model
 * that mixes stored grants with ones it derives writes the two methods itself.
 * What the interface buys either way is that a host can find its governed
 * models, and that a check can tell "answers from rbac" from "answers somehow".
 */
interface GrantedInterface extends UserInterface
{
}
