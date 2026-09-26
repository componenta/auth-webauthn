<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class WebAuthnReauthenticationHandler implements
    RequestHandlerInterface
{
    public function __construct(
        private WebAuthnService $webauthn,
        private AuthenticatedSessionIssuer $sessionIssuer,
        private AuthSessionGrantPublisher $publisher,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $identity = $request->getAttribute(IdentityInterface::class);
        $session = $request->getAttribute(AuthSession::class);
        $body = $request->getParsedBody();

        if (
            !$identity instanceof IdentityInterface
            || !$session instanceof AuthSession
            || !$identity->uuid->equals($session->subjectId)
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

        if (!is_string($credential)) {
            return $this->denied();
        }

        $attempt = $this->webauthn->validateAuthentication(
            $ceremonyId,
            $credential,
            $request->getUri()->getHost(),
        );

        if (
            $attempt === null
            || $attempt->bindingId !== null
            || !$attempt->subjectId->equals($identity->uuid)
        ) {
            return $this->denied();
        }

        $response = $this->responses->createResponse(204);

        if (!$this->webauthn->commitAuthentication($attempt)) {
            return $this->denied();
        }

        $grant = $this->sessionIssuer->reauthenticate(
            $session,
            $identity,
            $attempt->evidence,
        );

        return $this->publisher->publish(
            $request,
            $response,
            $grant,
        );
    }

    private function denied(): ResponseInterface
    {
        return $this->responses->createResponse(401)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
