<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class WebAuthnReauthenticationOptionsHandler implements
    RequestHandlerInterface
{
    public function __construct(
        private WebAuthnService $webauthn,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $identity = $request->getAttribute(IdentityInterface::class);

        if (!$identity instanceof IdentityInterface) {
            return $this->responses->createResponse(401);
        }

        $ceremony = $this->webauthn->beginAuthentication($identity->uuid);
        $response = $this->responses->createResponse(200);
        $response->getBody()->write(json_encode([
            'ceremony_id' => $ceremony->uuid->toString(),
            'options' => json_decode(
                $ceremony->optionsJson,
                true,
                64,
                JSON_THROW_ON_ERROR,
            ),
        ], JSON_THROW_ON_ERROR));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
