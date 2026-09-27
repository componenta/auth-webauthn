<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\WebAuthnLoginVerifyHandler;
use Componenta\Auth\AuthenticationGuardInterface;
use PHPUnit\Framework\TestCase;

final class AdmissionConfigurationTest extends TestCase
{
    public function testTheSharedAdmissionGuardIsRequiredAndCannotBeSilentlyOmitted(): void
    {
        $parameters = (new \ReflectionMethod(WebAuthnLoginVerifyHandler::class, '__construct'))->getParameters();
        $guard = $parameters[array_key_last($parameters)];
        self::assertSame(AuthenticationGuardInterface::class, (string) $guard->getType());
        self::assertFalse($guard->isOptional(), 'Credential issuance requires an explicit shared admission guard.');
        self::assertFalse($guard->isVariadic());
    }
}
