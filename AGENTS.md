# Working on naf/rbac

NAF is a small PHP framework with optional Composer plugins. Its core owns boot,
configuration, the service container, routing, events and PSR-7 responses. Prefer existing
NAF helpers, services and extension interfaces; keep application business rules in the host.
This package declares `type: naf-plugin` and is discovered after installation in a NAF host.
The plugin repository itself is not the application's web root.

Before changing code, read the [shared contribution workflow](https://github.com/nafphp/docs/blob/main/AGENT_WORKFLOW.md)
and [release procedure](https://github.com/nafphp/docs/blob/main/RELEASING.md).
In the multi-repository workspace, the same documents are in the sibling `docs/` checkout;
use the linked copies when working from a standalone clone. Preserve other contributors' work.
Review and update user documentation with every behavior change. Source fixes use an RC branch;
verified documentation-only changes can be merged and published by the agent.

## What this plugin does

Grants for NAF hosts: which roles exist, what each one carries, who holds them,
and who may change any of that.

A host declares its vocabulary in code and composes roles from it; this package stores the
grants and decides who may move them. `composer require naf/rbac`, then `db:migrate up` and
`rbac:sync`.

## What belongs here, and what does not

This package stores and decides. It does not own people: who exists, how they
sign in, whether they are active — all of that is the host's, and a change here
that starts reaching into a users table has gone wrong.

`naf/auth` stays free of a database. That is the reason this package exists as
its own thing rather than as a folder in there, and it is not a detail to
optimise away later.

## The one file to read first

`src/Policy/PrivilegePolicy.php`. Everything else moves rows; that file is the
product. Its methods are assertions, not questions — they return silently or
throw — so a rule that forgets to throw fails open. If you add one, add the test
beside it in `tests/Unit/PrivilegePolicyTest.php`, where each rule appears once,
named after the thing it prevents.

Two properties worth keeping:

- **No magic role name.** Everything hangs off `rbac:lockout_permission`. The
  moment a rule says `=== 'admin'`, a host can no longer name its own roles.
- **Invariants are asserted, not derived.** The guard that keeps the last
  administrator sits where the taking away happens, even though the other rules
  make it hard to reach: the actor holds the permission and may not target
  themselves, so one holder remains. That is a conclusion resting on a different
  rule, and an invariant that breaks when somebody relaxes something else
  somewhere else is not an invariant. `assertSomebodyKeepsTheKeys()` is public
  for the same reason -- deleting and deactivating accounts live in the host,
  and each of those paths has to ask before it acts.
- **A guard that can misfire is a guard people route around.** The same check
  applies only to installation-wide changes. Without that limit it refuses a
  board lead's ordinary edit whenever the person being edited happens to
  administer the installation -- a denial nobody can act on, because what it
  objects to is not what was being changed. ScopedGrantsTest holds that.
- **One place decides reach.** `Scope::covers()` and nothing else. The SQL in
  AssignmentRepository expresses the same rule as three equality checks so an
  index can serve it, and derives them from the same value -- if you change one,
  change both, and ScopeTest is where you find out that you did not.

## Running the tests

They need no host application, only `naf/database` for the migration base class:

```sh
NAF_HOST=/path/to/an/installation vendor/bin/phpunit
```

Everything runs against SQLite in memory. That is also why the migration knows
three drivers and not two — a package does not get to assume the host's database.

## Telling the host what moved

A grant change is dispatched as an object, so a host that keeps a history can record it:

```php
use Naf\Rbac\Events\GrantsChanged;

event()->listen(GrantsChanged::class, fn(GrantsChanged $moved) => …);
```

The class is the event name — the framework's `dispatch()` takes an object and uses its class,
which an IDE can follow and a typo cannot survive. It is announced from the controller rather
than the writer, because a service that reaches for an event dispatcher needs a booted
application to be usable at all, and this package's services are meant to be usable without
one.

This package keeps no history of its own. A history is a product decision; access control is
not.

## Views

`src/views/rbac/roles.phtml` is a fragment. It must stay one: a package that
renders its own heading and navigation inside somebody else's application looks
exactly like what it is. Styling goes through custom properties with neutral
defaults, so a host maps it to its own tokens without overriding rules.

## Verify

```sh
NAF_HOST=$PWD composer test   # 49 tests, SQLite in memory
composer style:check          # composer style:fix applies it
composer validate --strict
```

CI runs all three on every push. `NAF_HOST` only has to name something with `naf/database` in
its vendor tree; this package's own install is one.

User docs: [Roles and permissions](https://nafphp.github.io/docs/rbac/).

Follow the shared [PHP code style](https://github.com/nafphp/docs/blob/main/CODE_STYLE.md)
and `.php-cs-fixer.dist.php`. Keep logical steps and local names readable, preserving public
signatures and template output.
