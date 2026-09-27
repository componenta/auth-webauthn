<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Auth\WebAuthn\WebAuthnConfig;
use Componenta\Auth\WebAuthn\WebAuthnRegistrationCompleteHandler;
use Componenta\Auth\WebAuthn\WebAuthnRegistrationOptionsHandler;
use Componenta\Auth\WebAuthn\WebAuthnService;
use Componenta\Auth\WebAuthn\WebAuthnStoreInterface;
use Componenta\Auth\WebAuthn\WebAuthnValidator;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RegistrationAuthorizationTest extends TestCase
{
    /** @return iterable<string, array{string, int}> */
    public static function deniedRequests(): iterable
    {
        yield 'GET cannot register credentials' => ['GET', 405];
        yield 'identity alone cannot register credentials' => ['POST', 401];
    }

    #[DataProvider('deniedRequests')]
    public function testOptionsRequireAuthorization(string $method, int $status): void
    {
        $store = $this->createMock(WebAuthnStoreInterface::class);
        $store->expects(self::never())->method('allCredentials');
        $handler = new WebAuthnRegistrationOptionsHandler($this->service($store), new Psr17Factory(), $this->factorManagement());
        $response = $handler->handle($this->request($method)->withParsedBody(['username' => 'user', 'display_name' => 'User']));
        self::assertSame($status, $response->getStatusCode());
    }

    #[DataProvider('deniedRequests')]
    public function testCompletionRequiresAuthorization(string $method, int $status): void
    {
        $store = $this->createMock(WebAuthnStoreInterface::class);
        $store->expects(self::never())->method('findCeremony');
        $handler = new WebAuthnRegistrationCompleteHandler($this->service($store), new Psr17Factory(), $this->factorManagement());
        $response = $handler->handle($this->request($method)->withParsedBody(['ceremony_id' => (new UuidFactory())->generate()->toString(), 'credential' => '{}']));
        self::assertSame($status, $response->getStatusCode());
    }

    private function service(WebAuthnStoreInterface $store): WebAuthnService
    {
        $config = new WebAuthnConfig('example.com', 'Example', ['https://example.com']);
        return new WebAuthnService($config, $store, new WebAuthnCodec(), new WebAuthnValidator($config));
    }

    private function request(string $method): ServerRequest
    {
        $identity = new class((new UuidFactory())->generate()) implements IdentityInterface {
            public function __construct(public readonly UuidInterface $uuid) {}
        };
        return (new ServerRequest($method, 'https://example.com/factors/webauthn'))->withAttribute(IdentityInterface::class, $identity);
    }
    private function factorManagement(): \Componenta\Auth\Session\Http\FactorManagementGuard
    {
        return new \Componenta\Auth\Session\Http\FactorManagementGuard(
            $this->createStub(\Componenta\Auth\Session\AuthSessionRegistryInterface::class),
            new \Componenta\Auth\AuthenticationAdmission(
                $this->createStub(\Componenta\Auth\IdentityProviderInterface::class),
                $this->createStub(\Componenta\Auth\AuthenticationGuardInterface::class),
            ),
            new \Componenta\Auth\Session\AssuranceRequirement(['password'], maxAge: 300),
            new \Componenta\Clock\FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new Psr17Factory(),
            str_repeat('k', 32),
        );
    }

}
