<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\UuidInterface;

final readonly class WebAuthnAuthentication
{
    public function __construct(
        public UuidInterface $subjectId,
        public AuthenticationEvidence $evidence,
    ) {}
}
