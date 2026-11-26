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

## Database schema upgrade

`DatabaseWebAuthnStore` requires a `revision` column in the credential table.
Each accepted credential update increments it in the same conditional SQL update.
This preserves successful authentication for authenticators with a zero signature
counter when the credential record and timestamp remain unchanged, including on
drivers that report only changed rows. Credential identity, subject and expected
counter remain conditions of that update; the revision is internal storage state.

New databases should use the current files in `resources/schema`. For an existing
database, apply the matching migration **before deploying the updated PHP code**:

- [MySQL 8.4 migration](resources/migrations/2026-11-26-credential-revision/mysql-8.4.sql)
- [PostgreSQL migration](resources/migrations/2026-11-26-credential-revision/postgresql.sql)
- [SQLite migration](resources/migrations/2026-11-26-credential-revision/sqlite.sql)

Run the migration once. If the store uses a custom credential table name or a
Cycle database prefix, adjust the migration's table name accordingly. Existing
credentials receive the default revision of zero. Older package code remains
compatible with the added column, so the schema can be upgraded first.

## Version 2 compatibility

This line requires `componenta/auth-session-http ^2.0.1`, and therefore the
CSRF v3 browser security contract. Unsafe CSRF-protected requests must include
valid Origin/Referer evidence as well as an admitted CSRF token; missing source
metadata is denied, not bypassed.

See [CHANGELOG.md](CHANGELOG.md) for coordinated migration details.
Authentication still uses Componenta Auth's shared session issuer.
