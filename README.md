# naf/rbac

Roles, permissions, and the rules for handing them out.

`naf/auth` answers *is this person allowed to*. It deliberately says nothing
about where that answer comes from — it has no database and no migrations, and
its `UserInterface` puts it in writing. This package is one answer: grants kept
in tables, a vocabulary declared in code, and a policy that decides who may
change either.

## What it is for

Two products here already grew their own version of this, which is the usual
sign. If you need roles that an installation can edit — rather than a fixed list
in code — this is that, and the screens to do it with.

## Install

```sh
composer require naf/rbac
vendor/bin/naf db:migrate up
vendor/bin/naf rbac:sync
```

`rbac:sync` writes the roles installed packages declare. Run it after migrating
and after adding a package. It adds what is missing and never overwrites what
an installation decided.

## Declaring what can be granted

In your plugin's `bootstrap.php`:

```php
use Naf\Rbac\Definition\PermissionDefinition;
use Naf\Rbac\Definition\RoleDefinition;

use function Naf\Rbac\rbac;

rbac()->registry
    ->permission(
        new PermissionDefinition('users.view', 'Nutzer sehen', '', 'Nutzer', 10),
        new PermissionDefinition('users.invite', 'Nutzer einladen', '', 'Nutzer', 20),
    )
    ->role(new RoleDefinition(
        'admin',
        'Administrator',
        'Verwaltet diese Installation.',
        ['rbac.manage', 'users.view', 'users.invite'],
    ));
```

A declared permission is only *offerable*. It never grants itself to an existing
role, so installing a package cannot widen anybody's access.

## Answering with it

Your user model already implements `Naf\Auth\Identity\UserInterface`. Point its
two grant methods here and everything downstream — `auth()->can()`,
`requirePermission()` — works unchanged:

```php
public function getRoles(): iterable
{
    return rbac()->rolesOf((int) $this->getId());
}

public function getPermissions(): iterable
{
    return rbac()->permissionsOf((int) $this->getId());
}
```

Both are read once per request and cached. Call `rbac()->forget()` after a
change that a later part of the same request will read back.

## The rules

`PrivilegePolicy` is the whole of the authorization, and it is meant to be read:

1. You need `rbac.manage` at all.
2. **You cannot hand out what you do not hold.** This subsumes the rule other
   systems write separately as *only an administrator may make administrators*:
   if only they hold the managing permission, only they can grant a role that
   carries it. It also means your top role must hold every permission it is
   expected to be able to grant.
3. **You cannot manage an account that holds something you do not.** Otherwise
   the way around rule 2 is to strip somebody and rebuild them.
4. **Somebody has to be left who can still do this.** The last role carrying
   `rbac.manage` cannot be emptied or deleted.
5. Changing your own roles needs `rbac.manage.own`. It cannot be used to gain
   anything — rule 2 applies to yourself like to anybody else, so the most it
   does is rearrange or give up what is already held. What it is good for is an
   administrator who hands out roles that must not hand *themselves* out, such
   as HR or project management: that difference is a grant rather than a line of
   code. Rule 4 still applies, so it is no way to step off the last set of keys.

Which permission counts for rules 2 and 4 is `rbac:lockout_permission`, so a
host may call its top role whatever it likes and may have several that qualify.

Every denial throws `PrivilegedActionDenied` with a stable `reason` for logs and
tests, and a message for the person who tried.

## Places

A grant is a person, a role, and where it applies:

```php
use Naf\Rbac\Scope;

$rbac->assignments->assign(7, [$adminId]);                                 // everywhere
$rbac->assignments->assign(7, [$maintainerId], Scope::allOf('project'));   // on every board
$rbac->assignments->assign(7, [$memberId], Scope::of('project', 5));       // on board 5
```

Asking is the same shape:

```php
$rbac->allows(7, 'board.settings', Scope::of('project', 5));
```

Three spellings reach a place — everywhere, every instance of its kind, and that
instance — and `Scope::covers()` is the only thing that decides which.

**An installation-wide grant reaches inside every board.** That is a decision:
the alternative, an administrator locked out of a board, is a support request
rather than a safeguard. A host wanting real separation names the two abilities
differently instead of relying on reach.

A role says where it may be handed out at all, so an installation-wide role
cannot be granted on one board and a board role cannot be granted
installation-wide:

```php
new RoleDefinition('admin', 'Administrator', permissions: [...]);
new RoleDefinition('maintainer', 'Maintainer', permissions: [...], scopeType: 'project');
```

Editing a role is deliberately **not** scoped. A role is one object held in many
places, so changing what it carries reaches all of them — that is authority over
the installation, not over a board, and the policy asks for it accordingly.

## Adding a kind of place

The package knows a grant can attach to something, and nothing about what. A
host registers one source per kind, and every screen offers it from then on:

```php
use Naf\Rbac\Contracts\ScopeSourceInterface;

final class Boards implements ScopeSourceInterface
{
    public function type(): string   { return 'project'; }
    public function label(): string  { return 'Boards'; }

    /** @return array<string,string> */
    public function instances(): array
    {
        return $this->repository->namesById();   // 7 => 'Nafinity'
    }
}

rbac()->registry->scope(new Boards($repository));
```

Teams, tenants, single tickets: another registration, no change in here. The
type is a string the host chooses, and `Scope::of('team', 'design')` works the
moment something answers for `team`.

`instances()` is called while a screen renders, so it may return only what the
person granting is allowed to see. An empty list hides the kind.

## The screens

Both are fragments, not pages — a host that installs this already has somewhere
settings live, and a package cannot bring a shell without it looking bolted on.

```php
<?= partial('rbac/roles', ['return' => '/admin/settings']) ?>
<?= partial('rbac/grants', ['user' => 12, 'name' => 'Alice', 'return' => '/admin/users/12']) ?>
```

`rbac/roles` edits what roles carry. `rbac/grants` edits what one person holds
and where — every place in one form, submitted at once, because a person's
access is one decision and not a series of them.

The host owns people. This package never lists them, never creates them and
never deactivates them; it is handed one and says what they may do.

`src/Resources/public/assets/rbac.css` styles both through custom properties
with neutral defaults, so mapping them to a host's design is one block:

```css
.rbac-roles, .rbac-grants { --rbac-line: var(--line); --rbac-accent: var(--accent); }
```

Set `rbac:path` to `null` to register no endpoints and drive the services from
screens of your own.

## What this does not do

**Users.** Who exists, inviting them, deactivating them: that is the host's, and
this package only says what they may do.

**Permission definitions in the database.** Permissions come from code. One that
an administrator typed into a form grants nothing, because nothing checks it — a
row that looks like power and is not. Roles are what an installation composes
freely, from the vocabulary its packages declare.
