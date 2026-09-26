<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Identity\UuidInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class WebAuthnService
{
    public function __construct(
        private WebAuthnConfig $config,
        private WebAuthnStoreInterface $store,
        private WebAuthnCodec $codec,
        private WebAuthnValidator $validator,
    ) {}

    public function beginRegistration(
        UuidInterface $subjectId,
        string $username,
        string $displayName,
    ): WebAuthnCeremony {
        self::assertUserText($username, 'WebAuthn username');
        self::assertUserText($displayName, 'WebAuthn display name');

        $exclude = array_map(
            static fn(WebAuthnCredential $credential) =>
                $credential->record->getPublicKeyCredentialDescriptor(),
            $this->store->allCredentials($subjectId),
        );
        $timeout = $this->config->timeoutMs;
        /** @var positive-int $timeout */
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create(
                $this->config->rpName,
                $this->config->rpId,
            ),
            user: PublicKeyCredentialUserEntity::create(
                $username,
                $subjectId->toString(),
                $displayName,
            ),
            challenge: random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification:
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey:
                    AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
            ),
            attestation:
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $exclude,
            timeout: $timeout,
        );

        return $this->store->createCeremony(
            WebAuthnCeremonyType::Registration,
            $subjectId,
            null,
            $this->codec->encodeCreationOptions($options),
            $this->config->ceremonyTtl,
        );
    }

    public function completeRegistration(
        UuidInterface $subjectId,
        UuidInterface $ceremonyId,
        #[\SensitiveParameter]
        string $credentialJson,
        string $host,
    ): bool {
        $ceremony = $this->store->findCeremony(
            $ceremonyId,
            WebAuthnCeremonyType::Registration,
        );

        if (
            $ceremony === null
            || $ceremony->subjectId === null
            || !$ceremony->subjectId->equals($subjectId)
        ) {
            return false;
        }

        try {
            $options = $this->codec->decodeCreationOptions(
                $ceremony->optionsJson,
            );
            $credential = $this->codec->decodeBrowserCredential(
                $credentialJson,
            );
        } catch (\Throwable) {
            return false;
        }

        $response = $credential->response;

        if (!$response instanceof AuthenticatorAttestationResponse) {
            return false;
        }

        try {
            $record = $this->validator->register(
                $response,
                $options,
                $host,
            );
        } catch (\Throwable) {
            return false;
        }

        if (!hash_equals($subjectId->toString(), $record->userHandle)) {
            return false;
        }

        if (!$this->store->consumeCeremony(
            $ceremonyId,
            WebAuthnCeremonyType::Registration,
        )) {
            return false;
        }

        try {
            $this->store->insertCredential($subjectId, $record);
        } catch (\Throwable) {
            return false;
        }

        return true;
    }

    public function beginAuthentication(
        ?UuidInterface $subjectId = null,
        ?UuidInterface $bindingId = null,
    ): WebAuthnCeremony {
        $allow = $subjectId === null
            ? []
            : array_map(
                static fn(WebAuthnCredential $credential) =>
                    $credential->record->getPublicKeyCredentialDescriptor(),
                $this->store->allCredentials($subjectId),
            );

        $timeout = $this->config->timeoutMs;
        /** @var positive-int $timeout */
        $options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $this->config->rpId,
            allowCredentials: $allow,
            userVerification:
                PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: $timeout,
        );

        return $this->store->createCeremony(
            WebAuthnCeremonyType::Authentication,
            $subjectId,
            $bindingId,
            $this->codec->encodeRequestOptions($options),
            $this->config->ceremonyTtl,
        );
    }

    public function validateAuthentication(
        UuidInterface $ceremonyId,
        #[\SensitiveParameter]
        string $credentialJson,
        string $host,
    ): ?WebAuthnAuthenticationAttempt {
        $ceremony = $this->store->findCeremony(
            $ceremonyId,
            WebAuthnCeremonyType::Authentication,
        );

        if ($ceremony === null) {
            return null;
        }

        try {
            $options = $this->codec->decodeRequestOptions(
                $ceremony->optionsJson,
            );
            $credential = $this->codec->decodeBrowserCredential(
                $credentialJson,
            );
        } catch (\Throwable) {
            return null;
        }

        $response = $credential->response;

        if (!$response instanceof AuthenticatorAssertionResponse) {
            return null;
        }

        $stored = $this->store->findCredential($credential->rawId);

        if (
            $stored === null
            || (
                $ceremony->subjectId !== null
                && !$ceremony->subjectId->equals($stored->subjectId)
            )
        ) {
            return null;
        }

        $expectedCounter = $stored->record->counter;

        try {
            $updated = $this->validator->authenticate(
                $stored->record,
                $response,
                $options,
                $host,
                $response->userHandle,
            );
        } catch (\Throwable) {
            return null;
        }

        if (
            !hash_equals(
                $stored->subjectId->toString(),
                $updated->userHandle,
            )
        ) {
            return null;
        }

        return new WebAuthnAuthenticationAttempt(
            ceremonyId: $ceremonyId,
            subjectId: $stored->subjectId,
            bindingId: $ceremony->bindingId,
            evidence: WebAuthnEvidence::create(
                $response->authenticatorData->isUserVerified(),
            ),
            record: $updated,
            expectedCounter: $expectedCounter,
        );
    }

    public function commitAuthentication(
        WebAuthnAuthenticationAttempt $attempt,
    ): bool {
        if (!$this->store->consumeCeremony(
            $attempt->ceremonyId,
            WebAuthnCeremonyType::Authentication,
        )) {
            return false;
        }

        return $this->store->updateCredential(
            $attempt->subjectId,
            $attempt->record,
            $attempt->expectedCounter,
        );
    }

    private static function assertUserText(
        string $value,
        string $name,
    ): void {
        if (
            $value === ''
            || strlen($value) > 320
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($name . ' is invalid.');
        }
    }
}
