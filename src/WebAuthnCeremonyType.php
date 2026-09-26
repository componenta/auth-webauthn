<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn;

enum WebAuthnCeremonyType: string
{
    case Registration = 'registration';
    case Authentication = 'authentication';
}
