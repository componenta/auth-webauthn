<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\ChangedRowSqliteDriver;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

final class ChangedRowCredentialUpdateTest extends TestCase
{
    public function testRepeatedZeroCounterUpdateSucceedsAtTheSameTime(): void
    {
        $store = self::store();
        $subject = self::subject();
        $record = self::record($subject->toString(), 0);
        $store->insertCredential($subject, $record);

        self::assertTrue($store->updateCredential($subject, $record, 0));
        self::assertTrue($store->updateCredential($subject, $record, 0));

        $loaded = $store->findCredential($record->publicKeyCredentialId);
        self::assertNotNull($loaded);
        self::assertSame(0, $loaded->record->counter);
    }

    public function testStaleCounterCannotOverwriteAnUpdatedCredential(): void
    {
        $store = self::store();
        $subject = self::subject();
        $record = self::record($subject->toString(), 1);
        $store->insertCredential($subject, $record);

        self::assertTrue($store->updateCredential(
            $subject,
            self::record($subject->toString(), 2),
            1,
        ));
        self::assertFalse($store->updateCredential(
            $subject,
            self::record($subject->toString(), 3),
            1,
        ));

        $loaded = $store->findCredential($record->publicKeyCredentialId);
        self::assertNotNull($loaded);
        self::assertSame(2, $loaded->record->counter);
    }

    public function testDifferentSubjectCannotUpdateAnExistingCredential(): void
    {
        $store = self::store();
        $subject = self::subject();
        $otherSubject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abd',
        );
        $record = self::record($subject->toString(), 0);
        $store->insertCredential($subject, $record);

        self::assertFalse($store->updateCredential(
            $otherSubject,
            self::record($otherSubject->toString(), 1),
            0,
        ));

        $loaded = $store->findCredential($record->publicKeyCredentialId);
        self::assertNotNull($loaded);
        self::assertTrue($loaded->subjectId->equals($subject));
        self::assertSame(0, $loaded->record->counter);
    }

    public function testRemovedCredentialCannotBeUpdated(): void
    {
        $store = self::store();
        $subject = self::subject();
        $record = self::record($subject->toString(), 0);
        $store->insertCredential($subject, $record);
        $store->removeCredential($subject, $record->publicKeyCredentialId);

        self::assertFalse($store->updateCredential($subject, $record, 0));
        self::assertNull($store->findCredential($record->publicKeyCredentialId));
    }

    public function testMigrationPreservesAnExistingCredential(): void
    {
        self::requireSqlite();
        $database = new Database(
            'legacy',
            '',
            ChangedRowSqliteDriver::create(new SQLiteDriverConfig()),
        );
        $database->execute(<<<'SQL'
            CREATE TABLE auth_webauthn_credentials (
                credential_hash TEXT PRIMARY KEY,
                subject_uuid TEXT NOT NULL,
                record_json TEXT NOT NULL,
                counter INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NULL
            )
            SQL);
        $store = self::store($database);
        $subject = self::subject();
        $record = self::record($subject->toString(), 0);
        $store->insertCredential($subject, $record);
        $before = $store->findCredential($record->publicKeyCredentialId);
        self::assertNotNull($before);

        $migration = file_get_contents(
            dirname(__DIR__)
            . '/resources/migrations/2026-11-26-credential-revision/sqlite.sql',
        );
        self::assertIsString($migration);
        $database->execute($migration);

        self::assertEquals(
            $before,
            $store->findCredential($record->publicKeyCredentialId),
        );
        self::assertTrue($store->updateCredential($subject, $record, 0));
        self::assertTrue($store->updateCredential($subject, $record, 0));
    }

    private static function store(
        ?DatabaseInterface $database = null,
    ): DatabaseWebAuthnStore
    {
        self::requireSqlite();

        return new DatabaseWebAuthnStore(
            $database ?? SqliteDatabaseFixture::create(new SQLiteDriverConfig(
                driver: ChangedRowSqliteDriver::class,
            )),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new UuidFactory(),
            new WebAuthnCodec(),
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }

    private static function subject(): Uuid
    {
        return Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
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
}
