<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests;

use Componenta\Auth\WebAuthn\WebAuthnConfig;
use PHPUnit\Framework\TestCase;

final class WebAuthnConfigTest extends TestCase
{
    public function testAcceptsExactOriginForRpOrSubdomain(): void
    {
        $config = new WebAuthnConfig(
            rpId: 'example.com',
            rpName: 'Example',
            allowedOrigins: [
                'https://example.com',
                'https://admin.example.com:8443',
            ],
        );

        self::assertSame('example.com', $config->rpId);
    }

    public function testRejectsOriginWithPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WebAuthnConfig(
            rpId: 'example.com',
            rpName: 'Example',
            allowedOrigins: ['https://example.com/login'],
        );
    }

    public function testRejectsOriginOutsideRpId(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WebAuthnConfig(
            rpId: 'example.com',
            rpName: 'Example',
            allowedOrigins: ['https://evil.example.net'],
        );
    }
}
