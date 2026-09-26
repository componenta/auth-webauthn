<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

final class DatabaseWebAuthnStoreTest extends TestCase
{
    public function testCeremonyIsSingleUse(): void
    {
        self::requireSqlite();
        $store = self::store();
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $ceremony = $store->createCeremony(
            WebAuthnCeremonyType::Authentication,
            $subject,
            '{"challenge":"test"}',
            300,
        );

        self::assertNotNull($store->findCeremony(
            $ceremony->uuid,
            WebAuthnCeremonyType::Authentication,
        ));
        self::assertTrue($store->consumeCeremony(
            $ceremony->uuid,
            WebAuthnCeremonyType::Authentication,
        ));
        self::assertFalse($store->consumeCeremony(
            $ceremony->uuid,
            WebAuthnCeremonyType::Authentication,
        ));
        self::assertNull($store->findCeremony(
            $ceremony->uuid,
            WebAuthnCeremonyType::Authentication,
        ));
    }

    public function testCredentialUpdateUsesCounterCas(): void
    {
        self::requireSqlite();
        $store = self::store();
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $record = self::record($subject->toString(), 1);

        $store->insertCredential($subject, $record);

        $loaded = $store->findCredential(
            $record->publicKeyCredentialId,
        );
        self::assertNotNull($loaded);
        self::assertSame(1, $loaded->record->counter);

        $updated = self::record($subject->toString(), 2);

        self::assertTrue(
            $store->updateCredential($subject, $updated, 1),
        );
        self::assertFalse(
            $store->updateCredential($subject, self::record(
                $subject->toString(),
                3,
            ), 1),
        );
    }

    private static function store(): DatabaseWebAuthnStore
    {
        return new DatabaseWebAuthnStore(
            SqliteDatabaseFixture::create(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new UuidFactory(),
            new WebAuthnCodec(),
        );
    }

    private static function record(
        string $userHandle,
        int $counter,
    ): CredentialRecord {
        return CredentialRecord::create(
            publicKeyCredentialId: 'credential-id',
            type: 'public-key',
            transports: ['internal'],
            attestationType: 'none',
            trustPath: EmptyTrustPath::create(),
            aaguid: SymfonyUuid::fromString(
                '00000000-0000-0000-0000-000000000000',
            ),
            credentialPublicKey: 'credential-public-key',
            userHandle: $userHandle,
            counter: $counter,
            backupEligible: true,
            backupStatus: true,
            uvInitialized: true,
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
