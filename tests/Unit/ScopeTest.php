<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use Naf\Rbac\Scope;
use PHPUnit\Framework\TestCase;

/** The one rule that decides what applies where, on its own. */
final class ScopeTest extends TestCase
{
    public function testInstallationWideCoversEveryPlace(): void
    {
        $everywhere = Scope::everywhere();

        self::assertTrue($everywhere->covers(Scope::everywhere()));
        self::assertTrue($everywhere->covers(Scope::of('project', 7)));
        self::assertTrue($everywhere->covers(Scope::allOf('project')));
    }

    public function testOneBoardCoversOnlyItself(): void
    {
        $seven = Scope::of('project', 7);

        self::assertTrue($seven->covers(Scope::of('project', 7)));
        self::assertFalse($seven->covers(Scope::of('project', 8)));
        self::assertFalse($seven->covers(Scope::everywhere()));
    }

    public function testEveryBoardCoversAnyOneOfThem(): void
    {
        $all = Scope::allOf('project');

        self::assertTrue($all->covers(Scope::of('project', 7)));
        self::assertFalse($all->covers(Scope::of('team', 7)), 'a kind is not another kind');
        self::assertFalse($all->covers(Scope::everywhere()), 'every board is still not everywhere');
    }

    public function testItSurvivesStorageUnchanged(): void
    {
        foreach (['', 'project:7', 'project:*'] as $stored) {
            self::assertSame($stored, (string) Scope::parse($stored));
        }
    }

    public function testSomethingUnreadableIsNotQuietlyTreatedAsAPlace(): void
    {
        // Anything else would turn a typo into a grant somewhere unintended.
        self::assertSame('', (string) Scope::parse('nonsense'));
    }

    public function testAConcreteScopeCannotBeTheWildcardByAccident(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Scope::of('project', '*');
    }
}
