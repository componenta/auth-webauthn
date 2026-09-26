<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

final readonly class WebAuthnConfig
{
    /**
     * @param list<string> $allowedOrigins
     */
    public function __construct(
        public string $rpId,
        public string $rpName,
        public array $allowedOrigins,
        public int $ceremonyTtl = 300,
        public int $timeoutMs = 300_000,
    ) {
        if (
            $this->rpId === ''
            || strlen($this->rpId) > 253
            || preg_match('/\A[a-z0-9.-]+\z/D', $this->rpId) !== 1
        ) {
            throw new \InvalidArgumentException('WebAuthn RP ID is invalid.');
        }

        if (
            $this->rpName === ''
            || strlen($this->rpName) > 128
            || preg_match('/[\x00-\x1F\x7F]/', $this->rpName) === 1
        ) {
            throw new \InvalidArgumentException('WebAuthn RP name is invalid.');
        }

        if ($this->allowedOrigins === []) {
            throw new \InvalidArgumentException(
                'WebAuthn requires at least one allowed origin.',
            );
        }

        $rpId = strtolower($this->rpId);

        foreach ($this->allowedOrigins as $origin) {
            $parsed = parse_url($origin);

            if (
                !is_array($parsed)
                || strtolower((string) ($parsed['scheme'] ?? '')) !== 'https'
                || !is_string($parsed['host'] ?? null)
                || ($parsed['path'] ?? '') !== ''
                || isset($parsed['query'])
                || isset($parsed['fragment'])
                || isset($parsed['user'])
                || isset($parsed['pass'])
            ) {
                throw new \InvalidArgumentException(
                    'WebAuthn allowed origin must be an exact HTTPS origin.',
                );
            }

            $host = strtolower($parsed['host']);

            if (
                $host !== $rpId
                && !str_ends_with($host, '.' . $rpId)
            ) {
                throw new \InvalidArgumentException(
                    'WebAuthn allowed origin must belong to the RP ID.',
                );
            }
        }

        if (
            $this->ceremonyTtl < 30
            || $this->ceremonyTtl > 900
            || $this->timeoutMs < 1_000
            || $this->timeoutMs > 900_000
        ) {
            throw new \InvalidArgumentException(
                'WebAuthn ceremony timing is invalid.',
            );
        }
    }
}
