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

    public static function augment(
        AuthenticationEvidence $existing,
        bool $userVerified,
    ): AuthenticationEvidence {
        $proof = self::create($userVerified);

        return new AuthenticationEvidence(
            methods: array_values(array_unique([
                ...$existing->methods,
                ...$proof->methods,
            ])),
            capabilities: array_values(array_unique([
                ...$existing->capabilities,
                ...$proof->capabilities,
            ])),
        );
    }
}
