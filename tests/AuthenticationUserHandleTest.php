<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\RotationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCeremony;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Auth\WebAuthn\WebAuthnConfig;
use Componenta\Auth\WebAuthn\WebAuthnEvidence;
use Componenta\Auth\WebAuthn\WebAuthnReauthenticationHandler;
use Componenta\Auth\WebAuthn\WebAuthnReauthenticationOptionsHandler;
use Componenta\Auth\WebAuthn\WebAuthnService;
use Componenta\Auth\WebAuthn\WebAuthnValidator;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

final class AuthenticationUserHandleTest extends TestCase
{
    // Public synthetic test key, shared with the existing signed-assertion fixture.
    private const string AUTHENTICATOR_KEY = <<<'PEM'
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/rMgAKHTxBLBcJmC
        dTFLjHihSd2xOE/fPYKoYNxWLcqhRANCAAQJnGWMi9TSK/ImkXxZAeB2YqT+eOGF
        H4QO74KlwSXXnwB5KImnHnn80II+Q6CArNlEOOHr7OpXlgPwCfE3XxpQ
        -----END PRIVATE KEY-----
        PEM;

    private FrozenClock $clock;
    private UuidInterface $subject;
    private UuidInterface $otherSubject;
    private WebAuthnCodec $codec;
    private DatabaseWebAuthnStore $store;
    private WebAuthnService $service;
    private \OpenSSLAsymmetricKey $key;
    private string $credentialId;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) self::markTestSkipped('pdo_sqlite is required.');
        $this->clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $this->subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $this->otherSubject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd');
        $this->codec = new WebAuthnCodec();
        $config = new WebAuthnConfig('example.com', 'Example', ['https://example.com']);
        $this->store = new DatabaseWebAuthnStore(SqliteDatabaseFixture::create(), $this->clock, new UuidFactory(), $this->codec);
        $this->service = new WebAuthnService($config, $this->store, $this->codec, new WebAuthnValidator($config));
        $key = openssl_pkey_get_private(self::AUTHENTICATOR_KEY);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
        $this->key = $key;
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $this->credentialId = random_bytes(32);
        $coseKey = hex2bin('a5010203262001215820')
            . str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)
            . hex2bin('225820')
            . str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        $this->store->insertCredential($this->subject, CredentialRecord::create(
            publicKeyCredentialId: $this->credentialId,
            type: 'public-key',
            transports: ['usb'],
            attestationType: 'none',
            trustPath: EmptyTrustPath::create(),
            aaguid: SymfonyUuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: $coseKey,
            userHandle: $this->subject->toString(),
            counter: 0,
            backupEligible: false,
            backupStatus: false,
            uvInitialized: true,
        ));
    }

    #[DataProvider('userHandles')]
    public function testStoredCeremonySubjectDeterminesWhetherAUserHandleIsRequired(
        string $ceremonySubject,
        string $returnedHandle,
        bool $accepted,
    ): void {
        $subject = match ($ceremonySubject) {
            'known' => $this->subject,
            'other' => $this->otherSubject,
            default => null,
        };
        $handle = match ($returnedHandle) {
            'same' => $this->subject->toString(),
            'other' => $this->otherSubject->toString(),
            'empty' => '',
            default => null,
        };
        $ceremony = $this->service->beginAuthentication($subject);
        $attempt = $this->service->validateAuthentication(
            $ceremony->uuid,
            $this->assertion($ceremony, $handle),
            'example.com',
        );

        self::assertSame($accepted, $attempt !== null);
        self::assertSame(0, $this->store->findCredential($this->credentialId)?->record->counter);
        self::assertNotNull($this->store->findCeremony($ceremony->uuid, WebAuthnCeremonyType::Authentication));
        if ($attempt === null) return;

        self::assertTrue($attempt->subjectId->equals($this->subject));
        self::assertTrue($attempt->evidence->hasCapability('user_verified'));
        self::assertTrue($this->service->commitAuthentication($attempt));
        self::assertSame(1, $this->store->findCredential($this->credentialId)?->record->counter);
        self::assertFalse($this->service->commitAuthentication($attempt));
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function userHandles(): iterable
    {
        yield 'known user without returned handle' => ['known', 'null', true];
        yield 'known user with matching handle' => ['known', 'same', true];
        yield 'known user with foreign handle' => ['known', 'other', false];
        yield 'known user with empty non-null handle' => ['known', 'empty', false];
        yield 'credential belongs to another ceremony subject' => ['other', 'same', false];
        yield 'discoverable user with matching handle' => ['discoverable', 'same', true];
        yield 'discoverable user with foreign handle' => ['discoverable', 'other', false];
        yield 'discoverable user without handle' => ['discoverable', 'null', false];
        yield 'discoverable user with empty handle' => ['discoverable', 'empty', false];
    }

    #[DataProvider('publication')]
    public function testReauthenticationOptionsAndVerifyAcceptAnOptionalHandleAndPublishTheRotatedSession(
        bool $includeHandle,
        bool $deferred,
    ): void {
        $identity = new readonly class($this->subject) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $now = $this->clock->now();
        $sessionId = (new UuidFactory())->generate();
        $password = new AuthenticationEvidence(['password'], ['knowledge']);
        $session = new AuthSession($sessionId, $this->subject, $password, 1, $now, null, $now,
            $now->modify('+1800 seconds'), $now->modify('+28800 seconds'));
        $grant = new AuthSessionGrant(
            new AuthSession($sessionId, $this->subject, $password->merge(WebAuthnEvidence::create(true)), 2,
                $now, $now, $now, $now->modify('+1800 seconds'), $now->modify('+28800 seconds'),
                reauthenticationEvidence: WebAuthnEvidence::create(true)),
            SessionCredential::fromBytes(str_repeat('s', 32)),
        );
        $request = (new ServerRequest('POST', 'https://example.com/reauthenticate/webauthn'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(AuthSession::class, $session);
        $optionsResponse = (new WebAuthnReauthenticationOptionsHandler($this->service, new Psr17Factory()))->handle($request);
        $options = json_decode((string) $optionsResponse->getBody(), true, 64, JSON_THROW_ON_ERROR);
        self::assertSame(200, $optionsResponse->getStatusCode());
        self::assertSame(self::base64url($this->credentialId), $options['options']['allowCredentials'][0]['id']);
        $ceremony = $this->store->findCeremony(Uuid::fromString($options['ceremony_id']), WebAuthnCeremonyType::Authentication);
        self::assertNotNull($ceremony);
        self::assertTrue($ceremony->subjectId?->equals($this->subject));

        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $guard = $this->createMock(AuthenticationGuardInterface::class);
        $guard->expects(self::once())->method('check')->with($identity, self::callback(
            static fn(AuthenticationEvidence $proof): bool => $proof->hasMethod('webauthn') && $proof->hasCapability('user_verified'),
        ))->willReturn(null);
        $policy = new AuthSessionPolicy(1800, 28800);
        $policies = $this->createStub(AuthSessionPolicyProviderInterface::class);
        $policies->method('for')->willReturn($policy);
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::once())->method('rotate')->with($session, self::callback(
            static fn(AuthenticationEvidence $proof): bool => $proof->hasMethod('webauthn') && $proof->hasCapability('user_verified'),
        ), RotationReason::Reauthentication, $policy)->willReturn($grant);
        $sessions->expects(self::once())->method('isGrantCurrent')->with($grant)->willReturn(true);
        $sessions->expects(self::never())->method('revoke');
        $handler = new WebAuthnReauthenticationHandler(
            $this->service,
            new AuthenticatedSessionIssuer($sessions, $policies, new AuthenticationAdmission($identities, $guard)),
            new AuthSessionGrantPublisher($sessions, new SessionCookieTransport()),
            new Psr17Factory(),
        );
        $state = new CredentialTransportState();
        if ($deferred) $request = $request->withAttribute(CredentialTransportState::class, $state);
        $request = $request->withParsedBody([
            'ceremony_id' => $ceremony->uuid->toString(),
            'credential' => $this->assertion($ceremony, $includeHandle ? $this->subject->toString() : null),
        ]);

        $response = $handler->handle($request);

        self::assertSame(204, $response->getStatusCode());
        if ($deferred) {
            self::assertSame([], $response->getHeader('Set-Cookie'));
            $response = $state->apply($request, $response);
        }
        self::assertStringContainsString($grant->credential->toString(), $response->getHeaderLine('Set-Cookie'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame(1, $this->store->findCredential($this->credentialId)?->record->counter);
        self::assertNull($this->store->findCeremony($ceremony->uuid, WebAuthnCeremonyType::Authentication));
    }

    /** @return iterable<string, array{bool, bool}> */
    public static function publication(): iterable
    {
        yield 'null handle and direct publication' => [false, false];
        yield 'null handle and deferred publication' => [false, true];
        yield 'matching handle and direct publication' => [true, false];
        yield 'matching handle and deferred publication' => [true, true];
    }

    private function assertion(WebAuthnCeremony $ceremony, ?string $userHandle): string
    {
        $options = $this->codec->decodeRequestOptions($ceremony->optionsJson);
        $clientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => self::base64url($options->challenge),
            'origin' => 'https://example.com',
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
        $authData = hash('sha256', 'example.com', true) . chr(0x05) . pack('N', 1);
        self::assertTrue(openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256));

        return json_encode([
            'id' => self::base64url($this->credentialId),
            'rawId' => self::base64url($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::base64url($clientData),
                'authenticatorData' => self::base64url($authData),
                'signature' => self::base64url($signature),
                'userHandle' => $userHandle === null ? null : self::base64url($userHandle),
            ],
            'clientExtensionResults' => new \stdClass(),
        ], JSON_THROW_ON_ERROR);
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
