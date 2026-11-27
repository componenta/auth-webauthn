<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerAwareInterface;

final class CeremonyExpiryTest extends TestCase
{
    /** @return iterable<string, array{int, bool}> */
    public static function claimDelays(): iterable
    {
        yield 'finishes before expiry' => [29, true];
        yield 'finishes at expiry' => [30, false];
        yield 'finishes after expiry' => [31, false];
    }

    #[DataProvider('claimDelays')]
    public function testCeremonyMustRemainUnexpiredWhenItsClaimCompletes(
        int $delay,
        bool $accepted,
    ): void {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $uuids = new UuidFactory();
        $store = new DatabaseWebAuthnStore($database, $clock, $uuids, new WebAuthnCodec());
        $ceremony = $store->createCeremony(
            WebAuthnCeremonyType::Authentication,
            $uuids->generate(),
            $uuids->generate(),
            '{"challenge":"test"}',
            30,
        );
        $driver = $database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        $logger = new class($clock, $delay) extends AbstractLogger {
            public bool $advanced = false;

            public function __construct(
                private FrozenClock $clock,
                private int $delay,
            ) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if (!$this->advanced && str_starts_with((string) $message, 'UPDATE')) {
                    $this->advanced = true;
                    $this->clock->advance(sprintf('+%d seconds', $this->delay));
                }
            }
        };
        $driver->setLogger($logger);

        self::assertSame($accepted, $store->consumeCeremony($ceremony->uuid, $ceremony->type));
        self::assertTrue($logger->advanced, 'The ceremony must cross the delayed database boundary.');
        self::assertFalse($store->consumeCeremony($ceremony->uuid, $ceremony->type));
    }
}
