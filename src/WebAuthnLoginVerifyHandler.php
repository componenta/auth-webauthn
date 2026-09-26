<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class WebAuthnLoginVerifyHandler implements RequestHandlerInterface
{
    /** @var list<AuthenticationGuardInterface> */
    private array $guards;

    public function __construct(
        private WebAuthnService $webauthn,
        private IdentityProviderInterface $identities,
        private PreAuthenticationConsumer $preAuthentication,
        private PreAuthenticationGrantPublisher $preAuthenticationPublisher,
        private AuthenticatedSessionIssuer $sessionIssuer,
        private AuthSessionGrantPublisher $sessionPublisher,
        private SessionMetadataExtractorInterface $metadata,
        private ResponseFactoryInterface $responses,
        AuthenticationGuardInterface ...$guards,
    ) {
        $this->guards = array_values($guards);
    }

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        [$ceremonyId, $credentialJson] = self::payload($request);

        if ($ceremonyId === null || $credentialJson === null) {
            return $this->denied();
        }

        $attempt = $this->webauthn->validateAuthentication(
            $ceremonyId,
            $credentialJson,
            $request->getUri()->getHost(),
        );

        if ($attempt === null) {
            return $this->denied();
        }

        $identity = $this->identities->findByUuid($attempt->subjectId);

        if (
            !$identity instanceof IdentityInterface
            || !$identity->uuid->equals($attempt->subjectId)
        ) {
            return $this->denied();
        }

        foreach ($this->guards as $guard) {
            if ($guard->check($identity, $attempt->evidence) !== null) {
                return $this->denied();
            }
        }

        $response = $this->preAuthenticationPublisher->clear(
            $this->responses->createResponse(204),
        );

        if (
            $this->preAuthentication->consume($request) === null
            || !$this->webauthn->commitAuthentication($attempt)
        ) {
            return $this->preAuthenticationPublisher->clear(
                $this->denied(),
            );
        }

        $grant = $this->sessionIssuer->issue(
            $identity,
            $attempt->evidence,
            $this->metadata->extract($request),
        );

        return $this->sessionPublisher->publish(
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

    /**
     * @return array{0: \Componenta\Identity\UuidInterface|null, 1: string|null}
     */
    private static function payload(
        ServerRequestInterface $request,
    ): array {
        $body = $request->getParsedBody();

        if (!is_array($body)) {
            return [null, null];
        }

        $id = $body['ceremony_id'] ?? null;
        $credential = $body['credential'] ?? null;

        if (!is_string($id)) {
            return [null, null];
        }

        try {
            $uuid = Uuid::fromString($id);
        } catch (\InvalidArgumentException) {
            return [null, null];
        }

        if (is_array($credential)) {
            try {
                $credential = json_encode(
                    $credential,
                    JSON_THROW_ON_ERROR,
                );
            } catch (\JsonException) {
                return [null, null];
            }
        }

        return [$uuid, is_string($credential) ? $credential : null];
    }
}
