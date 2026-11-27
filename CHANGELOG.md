# Changelog

## Unreleased (3.0.0)

### Fixed

- Read the ceremony deadline from the writer and reject consumption that
  completes at or after that deadline. Keep the atomic single-use UPDATE;
  the expiry check adds one writer SELECT and does not change the schema.

### Dependency compatibility

- Require Componenta Auth 4, Auth Session 2 and Auth Session HTTP 3, including
  the CSRF 4 browser transport. Upgrade the authentication packages together;
  the previous Auth 3 and Session HTTP 2 dependency families are incompatible.
- Require `componenta/identity ^1.1.1` and test with `componenta/clock ^1.2.0`.

### Migration

- Both registration endpoints require an explicit
  `FactorManagementGuard` with an authoritative session registry, account
  admission, session-bound CSRF and a bounded assurance policy.
- Use `validateAuthentication()` followed by `commitAuthentication()`; the preliminary `WebAuthnAuthentication` DTO has been removed.

### Credential persistence

- Accept valid zero-counter credential updates even when the database reports
  changed rows and the record and timestamp are unchanged. The conditional update
  now increments an internal storage revision.
- Existing installations must apply the credential revision migration before
  deploying this code. See the [database schema upgrade](README.md#database-schema-upgrade).

## v2.0.0 (2026-10-10)

### Dependency compatibility
- Upgrade required `componenta/auth-session-http` from `^1.0` to `^2.0.1`; this adopts `componenta/http-csrf-middleware ^3.0` transitively.
- Keep the WebAuthn/passkey enrollment and authentication public contracts while sharing Componenta Auth sessions and their existing issuer.
- Update the main branch alias to `2.0.x-dev`.

### Migration
- Update the browser session transport and CSRF middleware as a compatible set; this major release cannot be installed with the old session-http 1.x family.
- Unsafe CSRF-protected browser operations require valid Origin/Referer and token validation; no permissive fallback is introduced.
- Verify actual session, account and CSRF flows after updating on PHP 8.4 / 8.5.

### Verification
- The release workflow checks Composer metadata, dependency advisories, PHPStan, and PHPUnit on PHP 8.4 and 8.5 before it publishes the stable GitHub tag.
