<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\WebAuthnEvidence;
use PHPUnit\Framework\TestCase;

final class WebAuthnEvidenceTest extends TestCase
{
    public function testPhishingResistanceDoesNotDependOnUvButUserVerificationDoes(): void
    {
        $withoutUv = WebAuthnEvidence::create(false);
        $withUv = WebAuthnEvidence::create(true);

        self::assertTrue(
            $withoutUv->hasCapability('phishing_resistant'),
        );
        self::assertFalse($withoutUv->hasCapability('user_verified'));
        self::assertTrue($withUv->hasCapability('user_verified'));
    }
}
