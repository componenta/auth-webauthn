<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

final readonly class WebAuthnCodec
{
    private SerializerInterface $serializer;

    public function __construct(?SerializerInterface $serializer = null)
    {
        $this->serializer = $serializer
            ?? (new WebauthnSerializerFactory(
                new AttestationStatementSupportManager(),
            ))->create();
    }

    public function encodeCreationOptions(
        PublicKeyCredentialCreationOptions $options,
    ): string {
        return $this->serializer->serialize($options, 'json');
    }

    public function decodeCreationOptions(
        #[\SensitiveParameter]
        string $json,
    ): PublicKeyCredentialCreationOptions {
        return $this->serializer->deserialize(
            $json,
            PublicKeyCredentialCreationOptions::class,
            'json',
        );
    }

    public function encodeRequestOptions(
        PublicKeyCredentialRequestOptions $options,
    ): string {
        return $this->serializer->serialize($options, 'json');
    }

    public function decodeRequestOptions(
        #[\SensitiveParameter]
        string $json,
    ): PublicKeyCredentialRequestOptions {
        return $this->serializer->deserialize(
            $json,
            PublicKeyCredentialRequestOptions::class,
            'json',
        );
    }

    public function decodeBrowserCredential(
        #[\SensitiveParameter]
        string $json,
    ): PublicKeyCredential {
        return $this->serializer->deserialize(
            $json,
            PublicKeyCredential::class,
            'json',
        );
    }

    public function encodeCredentialRecord(CredentialRecord $record): string
    {
        return $this->serializer->serialize($record, 'json');
    }

    public function decodeCredentialRecord(
        #[\SensitiveParameter]
        string $json,
    ): CredentialRecord {
        return $this->serializer->deserialize(
            $json,
            CredentialRecord::class,
            'json',
        );
    }
}
