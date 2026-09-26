<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use Webauthn\CredentialRecord;

final readonly class WebAuthnCredential
{
    public function __construct(
        public UuidInterface $subjectId,
        public CredentialRecord $record,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $lastUsedAt,
    ) {}
}
