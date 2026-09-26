<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class WebAuthnCeremony
{
    public function __construct(
        public UuidInterface $uuid,
        public WebAuthnCeremonyType $type,
        public ?UuidInterface $subjectId,
        public string $optionsJson,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if (
            $this->optionsJson === ''
            || $this->expiresAt <= $this->createdAt
        ) {
            throw new \InvalidArgumentException(
                'WebAuthn ceremony is invalid.',
            );
        }
    }
}
