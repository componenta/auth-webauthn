# Auth 3 development security integration

WebAuthnLoginVerifyHandler requires a single AuthenticationGuardInterface as
its final constructor argument. Use the same account-admission policy as the
AuthenticationAdmission passed to AuthenticatedSessionIssuer.

Both registration handlers require FactorManagementGuard as their third
constructor dependency. Configure its bounded AssuranceRequirement for an
existing permitted factor; wire distinct guard instances for distinct endpoint
policies when necessary. Neither identity alone, a remembered session, nor a
GET request authorizes registering a credential. The gate checks authoritative
session state, credential generation, account admission and session-bound CSRF.
Initial enrollment and replacement are distinct application policy decisions;
recent evidence does not imply authorization to replace every type of factor.

Login and reauthentication explicitly handle a terminal denial from the final
session issuer without passing it to the credential publisher. No migration
or database schema change is required by this integration change.
