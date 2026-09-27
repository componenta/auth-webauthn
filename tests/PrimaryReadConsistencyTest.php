<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

final class PrimaryReadConsistencyTest extends TestCase
{
    public function testNewCeremonyIsImmediatelyVisibleAndConsumptionIsImmediatelyObserved(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $writer = $this->store($primary);
        $reader = $this->store($split);
        $ceremony = $writer->createCeremony(WebAuthnCeremonyType::Authentication, null, null, '{}', 300);
        self::assertNotNull($reader->findCeremony($ceremony->uuid, $ceremony->type));
        $this->replicate($primary, $replica, 'auth_webauthn_ceremonies');
        self::assertTrue($writer->consumeCeremony($ceremony->uuid, $ceremony->type));
        self::assertNull($reader->findCeremony($ceremony->uuid, $ceremony->type));
    }

    public function testRemovedCredentialCannotRemainInAuthoritativeReads(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $subject = (new UuidFactory())->generate();
        $record = CredentialRecord::create(
            publicKeyCredentialId: 'credential-id', type: 'public-key',
            transports: ['internal'], attestationType: 'none', trustPath: EmptyTrustPath::create(),
            aaguid: SymfonyUuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: 'public-key', userHandle: $subject->toString(), counter: 0,
            backupEligible: true, backupStatus: true, uvInitialized: true,
        );
        $writer = $this->store($primary);
        $reader = $this->store($split);
        $writer->insertCredential($subject, $record);
        $this->replicate($primary, $replica, 'auth_webauthn_credentials');
        $writer->removeCredential($subject, $record->publicKeyCredentialId);
        self::assertNull($reader->findCredential($record->publicKeyCredentialId));
        self::assertSame([], $reader->allCredentials($subject));
    }

    /** @return array{DatabaseInterface, DatabaseInterface, DatabaseInterface} */
    private function databases(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $primary = SqliteDatabaseFixture::create();
        $replica = SqliteDatabaseFixture::create();
        return [$primary, $replica, new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ))];
    }

    private function store(DatabaseInterface $database): DatabaseWebAuthnStore
    {
        return new DatabaseWebAuthnStore($database, new FrozenClock('2030-01-01T00:00:00Z', 'UTC'), new UuidFactory(), new WebAuthnCodec());
    }

    private function replicate(DatabaseInterface $primary, DatabaseInterface $replica, string $table): void
    {
        foreach ($primary->select()->from($table)->run()->fetchAll() as $row) {
            $replica->insert($table)->values($row)->run();
        }
    }
}
