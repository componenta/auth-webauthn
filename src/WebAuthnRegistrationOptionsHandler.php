<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class WebAuthnRegistrationOptionsHandler implements
    RequestHandlerInterface
{
    public function __construct(
        private WebAuthnService $webauthn,
        private ResponseFactoryInterface $responses,
        private FactorManagementGuard $factorManagement,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $denial = $this->factorManagement->check($request);

        if ($denial !== null) {
            return $denial;
        }

        $identity = $request->getAttribute(IdentityInterface::class);
        $body = $request->getParsedBody();

        if (
            !$identity instanceof IdentityInterface
            || !is_array($body)
            || !is_string($body['username'] ?? null)
            || !is_string($body['display_name'] ?? null)
        ) {
            return $this->responses->createResponse(422);
        }

        try {
            $ceremony = $this->webauthn->beginRegistration(
                $identity->uuid,
                $body['username'],
                $body['display_name'],
            );
        } catch (\InvalidArgumentException) {
            return $this->responses->createResponse(422);
        }

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
