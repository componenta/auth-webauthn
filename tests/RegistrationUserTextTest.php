<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AssuranceRequirement;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionRegistryInterface;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfTokenManager;
use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Auth\WebAuthn\WebAuthnConfig;
use Componenta\Auth\WebAuthn\WebAuthnRegistrationOptionsHandler;
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

final class RegistrationUserTextTest extends TestCase
{
    /** @return iterable<string, array{string, string, int}> */
    public static function userText(): iterable
    {
        yield 'invalid UTF-8 username' => ["user\xE9", 'User', 422];
        yield 'invalid UTF-8 display name' => ['user', "User\xE9", 422];
        yield 'valid Unicode names' => ['élise', 'Ёлка 日本語', 200];
    }

    #[DataProvider('userText')]
    public function testRegistrationTreatsMalformedUserTextAsInputError(
        string $username,
        string $displayName,
        int $expectedStatus,
    ): void {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $uuids = new UuidFactory();
        $identity = new readonly class($uuids->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $now = $clock->now();
        $session = new AuthSession(
            $uuids->generate(),
            $identity->uuid,
            new AuthenticationEvidence(['password']),
            1,
            $now,
            null,
            $now,
            $now->modify('+30 minutes'),
            $now->modify('+8 hours'),
        );
        $registry = $this->createStub(AuthSessionRegistryInterface::class);
        $registry->method('find')->willReturn($session);
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $admissionGuard = $this->createStub(AuthenticationGuardInterface::class);
        $admissionGuard->method('check')->willReturn(null);
        $responses = new Psr17Factory();
        $csrfKey = str_repeat('k', 32);
        $factorManagement = new FactorManagementGuard(
            $registry,
            new AuthenticationAdmission($identities, $admissionGuard),
            new AssuranceRequirement(['password'], maxAge: 300),
            $clock,
            $responses,
            $csrfKey,
        );
        $codec = new WebAuthnCodec();
        $config = new WebAuthnConfig('example.com', 'Example', ['https://example.com']);
        $store = new DatabaseWebAuthnStore($database, $clock, $uuids, $codec);
        $handler = new WebAuthnRegistrationOptionsHandler(
            new WebAuthnService($config, $store, $codec, new WebAuthnValidator($config)),
            $responses,
            $factorManagement,
        );
        $request = (new ServerRequest('POST', 'https://example.com/webauthn/register'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(AuthSession::class, $session)
            ->withHeader('Origin', 'https://example.com')
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('X-CSRF-Token', (new AuthSessionCsrfTokenManager($session, $csrfKey))->generate())
            ->withParsedBody(['username' => $username, 'display_name' => $displayName]);

        $response = $handler->handle($request);

        self::assertSame($expectedStatus, $response->getStatusCode());
        self::assertSame(
            $expectedStatus === 200 ? 1 : 0,
            $database->select()->from('auth_webauthn_ceremonies')->count(),
        );

        if ($expectedStatus === 200) {
            $payload = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
            self::assertSame($username, $payload['options']['user']['name']);
            self::assertSame($displayName, $payload['options']['user']['displayName']);
        }
    }
}
