<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\AuthenticationEvidence;

final class WebAuthnEvidence
{
    private function __construct() {}

    public static function create(bool $userVerified): AuthenticationEvidence
    {
        $capabilities = [
            'possession',
            'phishing_resistant',
        ];

        if ($userVerified) {
            $capabilities[] = 'user_verified';
        }

        return new AuthenticationEvidence(
            methods: ['webauthn'],
            capabilities: $capabilities,
        );
    }


}
