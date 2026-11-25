<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\WebAuthn\WebAuthnCeremony;
use Componenta\Auth\WebAuthn\WebAuthnCeremonyType;
use Componenta\Auth\WebAuthn\WebAuthnCodec;
use Componenta\Auth\WebAuthn\WebAuthnConfig;
use Componenta\Auth\WebAuthn\WebAuthnLoginOptionsHandler;
use Componenta\Auth\WebAuthn\WebAuthnService;
use Componenta\Auth\WebAuthn\WebAuthnStoreInterface;
use Componenta\Auth\WebAuthn\WebAuthnValidator;
use Componenta\Identity\UuidFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class LoginOptionsPublicationTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function publicationFailures(): iterable
    {
        foreach (['body-stalled', 'body-throwing', 'Content-Type', 'Set-Cookie', 'X-Pre-Auth-Token'] as $stage) {
            yield $stage => [$stage];
        }
    }

    #[DataProvider('publicationFailures')]
    public function testPublicationFailureConsumesTheExactPreAuthenticationGrant(string $stage): void
    {
        $uuids = new UuidFactory();
        $now = new \DateTimeImmutable('2030-01-01T00:00:00Z');
        $grant = new PreAuthenticationGrant(
            new PreAuthenticationTransaction($uuids->generate(), $now, $now->modify('+300 seconds')),
            PreAuthenticationCredential::fromBytes(str_repeat('c', 32)),
            PreAuthenticationRequestToken::fromBytes(str_repeat('t', 32)),
        );
        $active = false;
        $manager = $this->createMock(PreAuthenticationManagerInterface::class);
        $manager->expects(self::once())->method('create')->willReturnCallback(
            static function () use ($grant, &$active): PreAuthenticationGrant {
                $active = true;
                return $grant;
            },
        );
        $manager->expects(self::once())->method('consume')
            ->with(self::identicalTo($grant->credential), self::identicalTo($grant->requestToken))
            ->willReturnCallback(static function () use ($grant, &$active): PreAuthenticationTransaction {
                $active = false;
                return $grant->transaction;
            });
        $manager->method('verify')->willReturnCallback(
            static function () use ($grant, &$active): ?PreAuthenticationTransaction {
                return $active ? $grant->transaction : null;
            },
        );
        $store = $this->createStub(WebAuthnStoreInterface::class);
        $store->method('createCeremony')->willReturn(new WebAuthnCeremony(
            $uuids->generate(), WebAuthnCeremonyType::Authentication, null, $grant->transaction->uuid,
            '{"challenge":"synthetic"}', $now, $now->modify('+300 seconds'),
        ));
        $config = new WebAuthnConfig('example.com', 'Example', ['https://example.com']);
        $service = new WebAuthnService($config, $store, new WebAuthnCodec(), new WebAuthnValidator($config));
        $failure = new \RuntimeException('Synthetic WebAuthn login publication failed.');
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $bytes) use ($stage, $failure): int {
                if ($stage === 'body-stalled') return 0;
                if ($stage === 'body-throwing') throw $failure;
                return strlen($bytes);
            },
        );
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn($stream);
        $response->method('getHeader')->willReturn([]);
        $response->method('withoutHeader')->willReturn($response);
        foreach (['withHeader', 'withAddedHeader'] as $method) {
            $response->method($method)->willReturnCallback(
                static function (string $name, mixed $value) use ($stage, $failure, $response): ResponseInterface {
                    if ($name === $stage) throw $failure;
                    return $response;
                },
            );
        }
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);
        $handler = new WebAuthnLoginOptionsHandler(
            $service, $manager,
            new PreAuthenticationGrantPublisher(new PreAuthenticationCookieTransport()),
            $responses,
        );
        $observed = null;

        try {
            $handler->handle(new ServerRequest('POST', 'https://example.com/webauthn/options'));
        } catch (\RuntimeException $exception) {
            $observed = $exception;
        }

        self::assertInstanceOf(\RuntimeException::class, $observed);
        if ($stage !== 'body-stalled') {
            self::assertSame($failure, $observed);
        }
        self::assertNull(
            $manager->verify($grant->credential, $grant->requestToken),
            'The unpublished pre-authentication transaction must be consumed.',
        );
    }
}
