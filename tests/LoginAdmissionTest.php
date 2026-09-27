<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Auth\WebAuthn\WebAuthnConfig;
use Componenta\Auth\WebAuthn\WebAuthnEvidence;
use Componenta\Auth\WebAuthn\WebAuthnLoginVerifyHandler;
use Componenta\Auth\WebAuthn\WebAuthnService;
use Componenta\Auth\WebAuthn\WebAuthnValidator;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Uid\Uuid as SymfonyUuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

final class LoginAdmissionTest extends TestCase
{
    /** @return iterable<string, array{bool, bool}> */
    public static function admission(): iterable
    {
        yield 'blocked account' => [true, false];
        yield 'blocked at final issuance' => [false, true];
        yield 'allowed account' => [false, false];
    }

    #[DataProvider('admission')]
    public function testAValidSignedAssertionStillRequiresTheSharedAdmissionGuard(bool $earlyBlocked, bool $finalBlocked): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $blocked = $earlyBlocked || $finalBlocked;
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $now = $clock->now();
        $uuids = new UuidFactory();
        $identity = new class($uuids->generate()) implements IdentityInterface {
            public function __construct(public readonly UuidInterface $uuid) {}
        };
        $pre = new PreAuthenticationTransaction($uuids->generate(), $now, $now->modify('+300 seconds'));
        $codec = new WebAuthnCodec();
        $config = new WebAuthnConfig('example.com', 'Example', ['https://example.com']);
        $store = new DatabaseWebAuthnStore(SqliteDatabaseFixture::create(), $clock, $uuids, $codec);
        $service = new WebAuthnService($config, $store, $codec, new WebAuthnValidator($config));

        // A locally generated virtual authenticator. It uses a real P-256
        // signature, not a mocked successful WebAuthn validation result.
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $credentialId = random_bytes(32);
        $coseKey = hex2bin('a5010203262001215820') . $details['ec']['x'] . hex2bin('225820') . $details['ec']['y'];
        $record = CredentialRecord::create(
            publicKeyCredentialId: $credentialId,
            type: 'public-key',
            transports: ['internal'],
            attestationType: 'none',
            trustPath: EmptyTrustPath::create(),
            aaguid: SymfonyUuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: $coseKey,
            userHandle: $identity->uuid->toString(),
            counter: 0,
            backupEligible: false,
            backupStatus: false,
            uvInitialized: true,
        );
        $store->insertCredential($identity->uuid, $record);
        $ceremony = $service->beginAuthentication($identity->uuid, $pre->uuid);
        $options = $codec->decodeRequestOptions($ceremony->optionsJson);
        $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => self::base64url($options->challenge), 'origin' => 'https://example.com', 'crossOrigin' => false], JSON_THROW_ON_ERROR);
        $authData = hash('sha256', 'example.com', true) . chr(0x05) . pack('N', 1);
        self::assertTrue(openssl_sign($authData . hash('sha256', $clientData, true), $signature, $key, OPENSSL_ALGO_SHA256));
        $browser = json_encode([
            'id' => self::base64url($credentialId),
            'rawId' => self::base64url($credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::base64url($clientData),
                'authenticatorData' => self::base64url($authData),
                'signature' => self::base64url($signature),
                'userHandle' => self::base64url($identity->uuid->toString()),
            ],
            'clientExtensionResults' => new \stdClass(),
        ], JSON_THROW_ON_ERROR);
        self::assertNotNull($service->validateAuthentication($ceremony->uuid, $browser, 'example.com'), 'The fixture must pass real cryptographic validation before testing the admission boundary.');

        $preManager = $this->createMock(PreAuthenticationManagerInterface::class);
        $preManager->expects(self::once())->method('verify')->willReturn($pre);
        $preManager->expects($earlyBlocked ? self::never() : self::once())->method('consume')->willReturn($pre);
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $guard = $this->createMock(AuthenticationGuardInterface::class);
        $guard->expects(self::exactly($earlyBlocked ? 1 : 2))->method('check')->with($identity, self::callback(static fn(AuthenticationEvidence $evidence): bool => $evidence->hasMethod('webauthn') && $evidence->hasCapability('user_verified')))->willReturnOnConsecutiveCalls($earlyBlocked ? new InvalidCredentials() : null, $finalBlocked ? new InvalidCredentials() : null);
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $grant = new AuthSessionGrant(new AuthSession($uuids->generate(), $identity->uuid, WebAuthnEvidence::create(true), 1, $now, $now, null, $now, $now->modify('+1800 seconds'), $now->modify('+28800 seconds')), SessionCredential::fromBytes(str_repeat('s', 32)));
        $sessions->expects($blocked ? self::never() : self::once())->method('create')->willReturn($grant);
        $sessions->expects($blocked ? self::never() : self::once())->method('isGrantCurrent')->willReturn(true);
        $policies = $this->createStub(AuthSessionPolicyProviderInterface::class);
        $policies->method('for')->willReturn(new AuthSessionPolicy(1800, 28800));
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects($blocked ? self::never() : self::once())->method('store')->willReturnCallback(static fn(ServerRequestInterface $request, ResponseInterface $response, object $payload): ResponseInterface => $response->withHeader('X-Test-Published', 'yes'));
        $cookies = new PreAuthenticationCookieTransport();
        $metadata = $this->createStub(SessionMetadataExtractorInterface::class);
        $metadata->method('extract')->willReturn([]);
        $handler = new WebAuthnLoginVerifyHandler($service, $identities, new PreAuthenticationConsumer($preManager, $cookies), new PreAuthenticationGrantPublisher($cookies), new AuthenticatedSessionIssuer($sessions, $policies, new \Componenta\Auth\AuthenticationAdmission($identities, $guard)), new AuthSessionGrantPublisher($sessions, $storage), $metadata, new Psr17Factory(), $guard);
        $request = (new ServerRequest('POST', 'https://example.com/login/webauthn'))
            ->withCookieParams(['__Host-auth_pre' => PreAuthenticationCredential::fromBytes(str_repeat('a', 32))->toString()])
            ->withHeader('X-Pre-Auth-Token', PreAuthenticationRequestToken::fromBytes(str_repeat('b', 32))->toString())
            ->withParsedBody(['ceremony_id' => $ceremony->uuid->toString(), 'credential' => $browser]);

        $response = $handler->handle($request);

        self::assertSame($blocked ? 401 : 204, $response->getStatusCode());
        self::assertSame($blocked ? '' : 'yes', $response->getHeaderLine('X-Test-Published'));
        self::assertSame($earlyBlocked ? 0 : 1, $store->findCredential($credentialId)?->record->counter);
        self::assertSame($earlyBlocked, $store->findCeremony($ceremony->uuid, WebAuthnCeremonyType::Authentication) !== null);
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
