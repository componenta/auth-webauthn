<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class WebAuthnLoginOptionsHandler implements RequestHandlerInterface
{
    public function __construct(
        private WebAuthnService $webauthn,
        private PreAuthenticationManagerInterface $preAuthentication,
        private PreAuthenticationGrantPublisher $preAuthenticationPublisher,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $response = $this->responses->createResponse(200);
        $preAuth = $this->preAuthentication->create();
        $ceremony = $this->webauthn->beginAuthentication();

        $response->getBody()->write(json_encode([
            'ceremony_id' => $ceremony->uuid->toString(),
            'options' => json_decode(
                $ceremony->optionsJson,
                true,
                64,
                JSON_THROW_ON_ERROR,
            ),
        ], JSON_THROW_ON_ERROR));

        return $this->preAuthenticationPublisher->publish(
            $response
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache'),
            $preAuth,
        );
    }
}
