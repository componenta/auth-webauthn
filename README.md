# Componenta Auth WebAuthn

WebAuthn/passkey registration, authentication and reauthentication for
Componenta Auth 3.

Cryptographic ceremony validation is delegated to `web-auth/webauthn-lib`.
Componenta owns only RP/origin configuration, short-lived one-time ceremonies,
credential persistence, identity binding, session issuance/rotation and
AuthenticationEvidence.

Discoverable browser login ceremonies are bound server-side to the exact
pre-authentication transaction that requested them, preventing assertion
forwarding/session-swapping across browsers.

Evidence reflects what the authenticator actually proved. A successful WebAuthn
assertion adds `webauthn`, `possession` and `phishing_resistant`.
`user_verified` is added separately only when the assertion's UV flag is set,
so privileged policy can explicitly require both phishing resistance and user
verification.

## Authentication service contract

`WebAuthnService::validateAuthentication()` returns a
`WebAuthnAuthenticationAttempt` or `null`. After checking admission and browser
binding, call `commitAuthentication()`; issue or rotate a session only when it
returns `true`. The unused preliminary `WebAuthnAuthentication` DTO has been removed.
