<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class WebAuthnRegistrationCompleteHandler implements
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
            || !is_string($body['ceremony_id'] ?? null)
        ) {
            return $this->denied();
        }

        try {
            $ceremonyId = Uuid::fromString($body['ceremony_id']);
        } catch (\InvalidArgumentException) {
            return $this->denied();
        }

        $credential = $body['credential'] ?? null;

        if (is_array($credential)) {
            try {
                $credential = json_encode(
                    $credential,
                    JSON_THROW_ON_ERROR,
                );
            } catch (\JsonException) {
                return $this->denied();
            }
        }

        if (
            !is_string($credential)
            || !$this->webauthn->completeRegistration(
                $identity->uuid,
                $ceremonyId,
                $credential,
                $request->getUri()->getHost(),
            )
        ) {
            return $this->denied();
        }

        return $this->responses->createResponse(204)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }

    private function denied(): ResponseInterface
    {
        return $this->responses->createResponse(400)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
