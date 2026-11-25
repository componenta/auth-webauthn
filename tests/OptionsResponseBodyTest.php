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
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\WebAuthn\DatabaseWebAuthnStore;
use Componenta\Auth\WebAuthn\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Auth\WebAuthn\WebAuthnConfig;
use Componenta\Auth\WebAuthn\WebAuthnLoginOptionsHandler;
use Componenta\Auth\WebAuthn\WebAuthnReauthenticationOptionsHandler;
use Componenta\Auth\WebAuthn\WebAuthnRegistrationOptionsHandler;
use Componenta\Auth\WebAuthn\WebAuthnService;
use Componenta\Auth\WebAuthn\WebAuthnValidator;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamInterface;

final class OptionsResponseBodyTest extends TestCase
{
    /** @return iterable<string, array{string, string}> */
    public static function responses(): iterable
    {
        foreach (['login', 'reauthentication', 'registration'] as $operation) {
            foreach (['complete', 'partial', 'stalled', 'throwing'] as $mode) {
                yield $operation . ' ' . $mode => [$operation, $mode];
            }
        }
    }

    #[DataProvider('responses')]
    public function testOptionsResponseIsCompleteOrFails(string $operation, string $mode): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $now = $clock->now();
        $uuids = new UuidFactory();
        $identity = new readonly class($uuids->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $codec = new WebAuthnCodec();
        $config = new WebAuthnConfig('example.com', 'Example', ['https://example.com']);
        $store = new DatabaseWebAuthnStore(SqliteDatabaseFixture::create(), $clock, $uuids, $codec);
        $service = new WebAuthnService($config, $store, $codec, new WebAuthnValidator($config));
        $preAuth = new PreAuthenticationGrant(
            new PreAuthenticationTransaction($uuids->generate(), $now, $now->modify('+300 seconds')),
            PreAuthenticationCredential::fromBytes(str_repeat('c', 32)),
            PreAuthenticationRequestToken::fromBytes(str_repeat('t', 32)),
        );
        $preAuthentication = $this->createStub(PreAuthenticationManagerInterface::class);
        $preAuthentication->method('create')->willReturn($preAuth);
        $request = (new ServerRequest('POST', 'https://example.com/webauthn/options'))
            ->withAttribute(IdentityInterface::class, $identity);

        $at = $now->modify('-60 seconds');
        $session = new AuthSession(
            $uuids->generate(), $identity->uuid, new AuthenticationEvidence(['password']),
            1, $at, null, $at, $now->modify('+30 minutes'), $now->modify('+8 hours'),
        );
        $registry = $this->createStub(AuthSessionRegistryInterface::class);
        $registry->method('find')->willReturn($session);
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $admissionGuard = $this->createStub(AuthenticationGuardInterface::class);
        $admissionGuard->method('check')->willReturn(null);
        $csrfKey = str_repeat('k', 32);
        $factorManagement = new FactorManagementGuard(
            $registry,
            new AuthenticationAdmission($identities, $admissionGuard),
            new AssuranceRequirement(['password'], maxAge: 300),
            $clock,
            new Psr17Factory(),
            $csrfKey,
        );
        $request = $request
            ->withAttribute(AuthSession::class, $session)
            ->withHeader('Origin', 'https://example.com')
            ->withHeader('X-CSRF-Token', (new AuthSessionCsrfTokenManager($session, $csrfKey))->generate())
            ->withParsedBody(['username' => 'user', 'display_name' => 'User']);

        $sink = new class {
            public string $body = '';
            public int $calls = 0;
        };
        $failure = new \RuntimeException('Synthetic WebAuthn options response stream failed.');
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $bytes) use ($mode, $sink, $failure): int {
                if (++$sink->calls > 1) {
                    if ($mode === 'stalled') {
                        return 0;
                    }
                    if ($mode === 'throwing') {
                        throw $failure;
                    }
                }
                $written = $mode === 'complete' ? strlen($bytes) : min(7, strlen($bytes));
                $sink->body .= substr($bytes, 0, $written);

                return $written;
            },
        );
        $stream->method('__toString')->willReturnCallback(static fn(): string => $sink->body);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn(new Response(200, [], $stream));
        $handler = match ($operation) {
            'login' => new WebAuthnLoginOptionsHandler(
                $service,
                $preAuthentication,
                new PreAuthenticationGrantPublisher(new PreAuthenticationCookieTransport()),
                $responses,
            ),
            'reauthentication' => new WebAuthnReauthenticationOptionsHandler($service, $responses),
            'registration' => new WebAuthnRegistrationOptionsHandler($service, $responses, $factorManagement),
        };

        if (in_array($mode, ['stalled', 'throwing'], true)) {
            $observed = null;
            try {
                $handler->handle($request);
            } catch (\RuntimeException $exception) {
                $observed = $exception;
            }

            self::assertInstanceOf(\RuntimeException::class, $observed,
                'Truncated WebAuthn options must not be returned as success.');
            if ($mode === 'throwing') {
                self::assertSame($failure, $observed);
            }
            self::assertSame(2, $sink->calls);

            return;
        }

        $response = $handler->handle($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertJson((string) $response->getBody());
        $body = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(['ceremony_id', 'options'], array_keys($body));
        $ceremony = $store->findCeremony(
            Uuid::fromString($body['ceremony_id']),
            $operation === 'registration' ? WebAuthnCeremonyType::Registration : WebAuthnCeremonyType::Authentication,
        );
        self::assertNotNull($ceremony);
        self::assertSame(json_decode($ceremony->optionsJson, true, flags: JSON_THROW_ON_ERROR), $body['options']);
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertStringContainsString('no-store', $response->getHeaderLine('Cache-Control'));
        if ($operation === 'login') {
            self::assertSame($preAuth->requestToken->toString(), $response->getHeaderLine('X-Pre-Auth-Token'));
            self::assertStringContainsString($preAuth->credential->toString(), $response->getHeaderLine('Set-Cookie'));
        }
    }
}
