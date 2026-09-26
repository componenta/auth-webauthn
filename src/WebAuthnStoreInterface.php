<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Identity\UuidInterface;
use Webauthn\CredentialRecord;

interface WebAuthnStoreInterface
{
    public function createCeremony(
        WebAuthnCeremonyType $type,
        ?UuidInterface $subjectId,
        ?UuidInterface $bindingId,
        string $optionsJson,
        int $ttlSeconds,
    ): WebAuthnCeremony;

    public function findCeremony(
        UuidInterface $ceremonyId,
        WebAuthnCeremonyType $type,
    ): ?WebAuthnCeremony;

    public function consumeCeremony(
        UuidInterface $ceremonyId,
        WebAuthnCeremonyType $type,
    ): bool;

    public function insertCredential(
        UuidInterface $subjectId,
        CredentialRecord $record,
    ): void;

    public function findCredential(
        #[\SensitiveParameter]
        string $credentialId,
    ): ?WebAuthnCredential;

    /** @return list<WebAuthnCredential> */
    public function allCredentials(UuidInterface $subjectId): array;

    public function updateCredential(
        UuidInterface $subjectId,
        CredentialRecord $record,
        int $expectedCounter,
    ): bool;

    public function removeCredential(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $credentialId,
    ): void;
}
