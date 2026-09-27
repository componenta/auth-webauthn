<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactoryInterface;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;
use Webauthn\CredentialRecord;

final readonly class DatabaseWebAuthnStore implements WebAuthnStoreInterface
{
    private const string DATE_FORMAT = 'Y-m-d H:i:s.u';

    public function __construct(
        private DatabaseInterface $database,
        private ClockInterface $clock,
        private UuidFactoryInterface $uuids,
        private WebAuthnCodec $codec,
        private string $ceremonyTable = 'auth_webauthn_ceremonies',
        private string $credentialTable = 'auth_webauthn_credentials',
    ) {
        foreach ([$this->ceremonyTable, $this->credentialTable] as $table) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $table) !== 1) {
                throw new \InvalidArgumentException(
                    'WebAuthn table name is invalid.',
                );
            }
        }
    }

    #[\Override]
    public function createCeremony(
        WebAuthnCeremonyType $type,
        ?UuidInterface $subjectId,
        ?UuidInterface $bindingId,
        string $optionsJson,
        int $ttlSeconds,
    ): WebAuthnCeremony {
        if (
            $optionsJson === ''
            || $ttlSeconds < 30
            || $ttlSeconds > 900
        ) {
            throw new \InvalidArgumentException(
                'WebAuthn ceremony payload is invalid.',
            );
        }

        $uuid = $this->uuids->generate();
        $now = $this->now();
        $expiresAt = $now->modify(sprintf('+%d seconds', $ttlSeconds));

        $this->database->insert($this->ceremonyTable)->values([
            'uuid' => $uuid->toString(),
            'type' => $type->value,
            'subject_uuid' => $subjectId?->toString(),
            'binding_uuid' => $bindingId?->toString(),
            'options_json' => $optionsJson,
            'created_at' => $this->format($now),
            'expires_at' => $this->format($expiresAt),
            'used_at' => null,
        ])->run();

        return new WebAuthnCeremony(
            $uuid,
            $type,
            $subjectId,
            $bindingId,
            $optionsJson,
            $now,
            $expiresAt,
        );
    }

    #[\Override]
    public function findCeremony(
        UuidInterface $ceremonyId,
        WebAuthnCeremonyType $type,
    ): ?WebAuthnCeremony {
        $now = $this->format($this->now());
        $row = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        )
            ->from($this->ceremonyTable)
            ->where('uuid', $ceremonyId->toString())
            ->where('type', $type->value)
            ->where('used_at', null)
            ->where('expires_at', '>', $now)
            ->run()
            ->fetch();

        return is_array($row) ? $this->hydrateCeremony($row) : null;
    }

    #[\Override]
    public function consumeCeremony(
        UuidInterface $ceremonyId,
        WebAuthnCeremonyType $type,
    ): bool {
        $now = $this->format($this->now());

        return $this->database->update($this->ceremonyTable)
            ->where('uuid', $ceremonyId->toString())
            ->where('type', $type->value)
            ->where('used_at', null)
            ->where('expires_at', '>', $now)
            ->values(['used_at' => $now])
            ->run() === 1;
    }

    #[\Override]
    public function insertCredential(
        UuidInterface $subjectId,
        CredentialRecord $record,
    ): void {
        if (!hash_equals($subjectId->toString(), $record->userHandle)) {
            throw new \InvalidArgumentException(
                'WebAuthn credential user handle does not match subject.',
            );
        }

        $this->database->insert($this->credentialTable)->values([
            'credential_hash' => self::credentialHash(
                $record->publicKeyCredentialId,
            ),
            'subject_uuid' => $subjectId->toString(),
            'record_json' => $this->codec->encodeCredentialRecord($record),
            'counter' => $record->counter,
            'created_at' => $this->format($this->now()),
            'last_used_at' => null,
        ])->run();
    }

    #[\Override]
    public function findCredential(
        #[\SensitiveParameter]
        string $credentialId,
    ): ?WebAuthnCredential {
        if ($credentialId === '') {
            return null;
        }

        $row = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        )
            ->from($this->credentialTable)
            ->where(
                'credential_hash',
                self::credentialHash($credentialId),
            )
            ->run()
            ->fetch();

        if (!is_array($row)) {
            return null;
        }

        $record = $this->codec->decodeCredentialRecord(
            self::stringValue($row, 'record_json'),
        );

        if (!hash_equals($credentialId, $record->publicKeyCredentialId)) {
            throw new \UnexpectedValueException(
                'Persisted WebAuthn credential hash collision detected.',
            );
        }

        return $this->hydrateCredential($row, $record);
    }

    #[\Override]
    public function allCredentials(UuidInterface $subjectId): array
    {
        $rows = $this->database->select()->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        )
            ->from($this->credentialTable)
            ->where('subject_uuid', $subjectId->toString())
            ->orderBy('created_at', 'ASC')
            ->run()
            ->fetchAll();
        $result = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $result[] = $this->hydrateCredential(
                $row,
                $this->codec->decodeCredentialRecord(
                    self::stringValue($row, 'record_json'),
                ),
            );
        }

        return $result;
    }

    #[\Override]
    public function updateCredential(
        UuidInterface $subjectId,
        CredentialRecord $record,
        int $expectedCounter,
    ): bool {
        if (
            $expectedCounter < 0
            || !hash_equals($subjectId->toString(), $record->userHandle)
        ) {
            return false;
        }

        return $this->database->update($this->credentialTable)
            ->where(
                'credential_hash',
                self::credentialHash($record->publicKeyCredentialId),
            )
            ->where('subject_uuid', $subjectId->toString())
            ->where('counter', $expectedCounter)
            ->values([
                'record_json' => $this->codec->encodeCredentialRecord($record),
                'counter' => $record->counter,
                'last_used_at' => $this->format($this->now()),
            ])
            ->run() === 1;
    }

    #[\Override]
    public function removeCredential(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $credentialId,
    ): void {
        if ($credentialId === '') {
            return;
        }

        $this->database->delete($this->credentialTable)
            ->where(
                'credential_hash',
                self::credentialHash($credentialId),
            )
            ->where('subject_uuid', $subjectId->toString())
            ->run();
    }

    public function cleanupCeremonies(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > 10_000) {
            throw new \InvalidArgumentException(
                'WebAuthn cleanup limit is out of bounds.',
            );
        }

        $now = $this->format($this->now());
        $rows = $this->database->select('uuid')->withDriver(
            $this->database->getDriver(DatabaseInterface::WRITE),
            $this->database->getPrefix(),
        )
            ->from($this->ceremonyTable)
            ->where(static function (mixed $query) use ($now): void {
                if (!$query instanceof \Cycle\Database\Query\SelectQuery) {
                    throw new \LogicException(
                        'Cycle must provide a SelectQuery.',
                    );
                }

                $query->where('expires_at', '<=', $now)
                    ->orWhere('used_at', '!=', null);
            })
            ->limit($limit)
            ->run()
            ->fetchAll();
        $ids = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['uuid'] ?? null)) {
                $ids[] = $row['uuid'];
            }
        }

        return $ids === []
            ? 0
            : $this->database->delete($this->ceremonyTable)
                ->where('uuid', 'IN', $ids)
                ->run();
    }

    /** @param array<array-key, mixed> $row */
    private function hydrateCeremony(array $row): WebAuthnCeremony
    {
        $subject = $row['subject_uuid'] ?? null;
        $binding = $row['binding_uuid'] ?? null;

        return new WebAuthnCeremony(
            Uuid::fromString(self::stringValue($row, 'uuid')),
            WebAuthnCeremonyType::from(
                self::stringValue($row, 'type'),
            ),
            $subject === null
                ? null
                : Uuid::fromString(self::stringValue($row, 'subject_uuid')),
            $binding === null
                ? null
                : Uuid::fromString(self::stringValue($row, 'binding_uuid')),
            self::stringValue($row, 'options_json'),
            $this->date(self::stringValue($row, 'created_at')),
            $this->date(self::stringValue($row, 'expires_at')),
        );
    }

    /** @param array<array-key, mixed> $row */
    private function hydrateCredential(
        array $row,
        CredentialRecord $record,
    ): WebAuthnCredential {
        $lastUsedAt = $row['last_used_at'] ?? null;

        return new WebAuthnCredential(
            Uuid::fromString(self::stringValue($row, 'subject_uuid')),
            $record,
            $this->date(self::stringValue($row, 'created_at')),
            $lastUsedAt === null
                ? null
                : $this->date(self::stringValue($row, 'last_used_at')),
        );
    }

    private static function credentialHash(
        #[\SensitiveParameter]
        string $credentialId,
    ): string {
        return hash(
            'sha256',
            "componenta-auth-webauthn-credential-v1\0" . $credentialId,
        );
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $date): string
    {
        return $date->setTimezone(new DateTimeZone('UTC'))
            ->format(self::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        $timezone = new DateTimeZone('UTC');

        foreach (['!Y-m-d H:i:s.u', '!Y-m-d H:i:s'] as $format) {
            $date = DateTimeImmutable::createFromFormat(
                $format,
                $value,
                $timezone,
            );

            if ($date instanceof DateTimeImmutable) {
                return $date;
            }
        }

        throw new \UnexpectedValueException(
            'Persisted WebAuthn timestamp is invalid.',
        );
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" is invalid.', $key),
            );
        }

        return (string) $value;
    }
}
