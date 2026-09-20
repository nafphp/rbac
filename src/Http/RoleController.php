<?php

declare(strict_types=1);

namespace Naf\Rbac\Http;

use Naf\Rbac\Exceptions\PrivilegedActionDenied;
use Naf\Rbac\Rbac;
use Psr\Http\Message\ResponseInterface;

use function Naf\Auth\auth;
use function Naf\json;
use function Naf\redirect;
use function Naf\request;

/**
 * Saving a role, and taking one away.
 *
 * Both answer JSON or a redirect depending on what was asked for, so the same
 * endpoint serves a host that enhances its forms and one that does not. Neither
 * decides anything: the policy is asked first and speaks by throwing.
 *
 * @internal
 */
final readonly class RoleController
{
    public function __construct(private Rbac $rbac)
    {
    }

    public function save(): ResponseInterface
    {
        return $this->attempt(function (array $body): string {
            $actor       = $this->actorId();
            $id          = ($body['id'] ?? '') === '' ? null : (int) $body['id'];
            $permissions = array_values(array_filter(
                array_map(strval(...), (array) ($body['permissions'] ?? [])),
                static fn(string $name) => $name !== '',
            ));

            $this->rbac->policy->assertRoleChange($actor, $id, $permissions);

            $label       = trim((string) ($body['label'] ?? ''));
            $description = trim((string) ($body['description'] ?? ''));
            if ($label === '') {
                return 'Ein Name wird benötigt.';
            }

            if ($id === null) {
                $this->rbac->roles->create($this->keyFor($label), $label, $description, $permissions);
            } else {
                $this->rbac->roles->update($id, $label, $description, $permissions);
            }

            $this->rbac->forget();

            return '';
        });
    }

    public function delete(): ResponseInterface
    {
        return $this->attempt(function (array $body): string {
            $id = (int) ($body['id'] ?? 0);
            $this->rbac->policy->assertRoleDeletion($this->actorId(), $id);
            $this->rbac->roles->delete($id);
            $this->rbac->forget();

            return '';
        });
    }

    /** @param callable(array<string,mixed>):string $operation returns an error message, or '' */
    private function attempt(callable $operation): ResponseInterface
    {
        $wantsJson = str_contains(request()->getHeaderLine('Accept'), 'application/json');
        $back      = (string) (request()->getParsedBody()['return'] ?? '/');

        try {
            $message = $operation((array) request()->getParsedBody());
        } catch (PrivilegedActionDenied $denied) {
            // 403 and not 400: the request was understood and refused, and the
            // reason is stable enough for a host to branch on.
            return $wantsJson
                ? json(['message' => $denied->getMessage(), 'reason' => $denied->reason], 403)
                : redirect($back, 303);
        }

        if ($message !== '') {
            return $wantsJson ? json(['message' => $message], 422) : redirect($back, 303);
        }

        return $wantsJson ? json(['url' => $back]) : redirect($back, 303);
    }

    private function actorId(): int
    {
        return (int) (auth()->user()?->getIdentifier() ?? 0);
    }

    /** A stable key from a label, so rules and code can name a role. */
    private function keyFor(string $label): string
    {
        $key = preg_replace('/[^a-z0-9]+/', '-', mb_strtolower($label)) ?? '';
        $key = trim($key, '-');

        return $key === '' ? 'rolle-' . bin2hex(random_bytes(3)) : $key;
    }
}
