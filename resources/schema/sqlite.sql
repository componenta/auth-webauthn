CREATE TABLE auth_webauthn_ceremonies (
    uuid TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    subject_uuid TEXT NULL,
    options_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT NULL
);

CREATE INDEX auth_webauthn_ceremony_expiry
    ON auth_webauthn_ceremonies(expires_at, used_at);

CREATE TABLE auth_webauthn_credentials (
    credential_hash TEXT PRIMARY KEY,
    subject_uuid TEXT NOT NULL,
    record_json TEXT NOT NULL,
    counter INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT NULL
);

CREATE INDEX auth_webauthn_subject
    ON auth_webauthn_credentials(subject_uuid);
