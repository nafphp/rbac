<?php

declare(strict_types=1);

namespace Naf\Rbac\Http;

use Naf\Rbac\Exceptions\PrivilegedActionDenied;
use Naf\Rbac\Service\GrantWriter;
use Psr\Http\Message\ResponseInterface;

use function Naf\Auth\auth;
use function Naf\json;
use function Naf\redirect;
use function Naf\request;

/**
 * What one person holds, everywhere, in one submit.
 *
 * The form sends every place at once because the screen shows every place at
 * once; GrantWriter is what makes that a single decision rather than a series
 * of them.
 *
 * @internal
 */
final readonly class GrantController
{
    public function __construct(private GrantWriter $writer)
    {
    }

    public function save(): ResponseInterface
    {
        $body      = (array) request()->getParsedBody();
        $wantsJson = str_contains(request()->getHeaderLine('Accept'), 'application/json');
        $back      = (string) ($body['return'] ?? '/');
        $target    = (int) ($body['user'] ?? 0);

        if ($target <= 0) {
            return $wantsJson ? json(['message' => 'Es fehlt die Person.'], 422) : redirect($back, 303);
        }

        try {
            $this->writer->apply($this->actorId(), $target, $this->grantsIn($body));
        } catch (PrivilegedActionDenied $denied) {
            return $wantsJson
                ? json(['message' => $denied->getMessage(), 'reason' => $denied->reason], 403)
                : redirect($back, 303);
        }

        return $wantsJson ? json(['url' => $back]) : redirect($back, 303);
    }

    /**
     * Read `roleId|scope` pairs out of the form.
     *
     * Anything unparseable is dropped rather than guessed at: a malformed pair
     * turned into a grant somewhere is the one mistake this must not make.
     *
     * @param array<string, mixed> $body
     * @return list<array{role:int,scope:string}>
     */
    private function grantsIn(array $body): array
    {
        $grants = [];
        foreach ((array) ($body['grants'] ?? []) as $pair) {
            if (!is_string($pair) || !str_contains($pair, '|')) {
                continue;
            }

            [$role, $scope] = explode('|', $pair, 2);
            if (!ctype_digit($role) || (int) $role <= 0) {
                continue;
            }

            $grants[] = ['role' => (int) $role, 'scope' => $scope];
        }

        return $grants;
    }

    private function actorId(): int
    {
        return (int) (auth()->user()?->getIdentifier() ?? 0);
    }
}
