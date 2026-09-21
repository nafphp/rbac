# naf/rbac

Roles, permissions, and the rules for handing them out. `naf/auth` answers *is this
person allowed to* and says nothing about where that answer comes from; this is one
answer — grants kept in tables, a vocabulary declared in code, and a policy that
decides who may change either.

## Documentation

<https://nafphp.github.io/docs/rbac/>

## Install

```sh
composer require naf/rbac
vendor/bin/naf db:migrate up
vendor/bin/naf rbac:sync
```

## License

MIT
