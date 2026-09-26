<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\UuidInterface;
use Webauthn\CredentialRecord;

final readonly class WebAuthnAuthenticationAttempt
{
    public function __construct(
        public UuidInterface $ceremonyId,
        public UuidInterface $subjectId,
        public ?UuidInterface $bindingId,
        public AuthenticationEvidence $evidence,
        public CredentialRecord $record,
        public int $expectedCounter,
    ) {}
}
