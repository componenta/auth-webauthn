<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

final readonly class WebAuthnValidator
{
    private AuthenticatorAttestationResponseValidator $registration;
    private AuthenticatorAssertionResponseValidator $authentication;

    public function __construct(WebAuthnConfig $config)
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($config->allowedOrigins);

        $this->registration = new AuthenticatorAttestationResponseValidator(
            $factory->creationCeremony(),
        );
        $this->authentication = new AuthenticatorAssertionResponseValidator(
            $factory->requestCeremony(),
        );
    }

    public function register(
        AuthenticatorAttestationResponse $response,
        PublicKeyCredentialCreationOptions $options,
        string $host,
    ): CredentialRecord {
        return $this->registration->check($response, $options, $host);
    }

    public function authenticate(
        CredentialRecord $record,
        AuthenticatorAssertionResponse $response,
        PublicKeyCredentialRequestOptions $options,
        string $host,
        ?string $userHandle,
    ): CredentialRecord {
        return $this->authentication->check(
            $record,
            $response,
            $options,
            $host,
            $userHandle,
        );
    }
}
