CREATE TABLE auth_webauthn_ceremonies (
    uuid UUID PRIMARY KEY,
    type VARCHAR(32) NOT NULL,
    subject_uuid UUID NULL,
    binding_uuid UUID NULL,
    options_json TEXT NOT NULL,
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    used_at TIMESTAMP(6) WITHOUT TIME ZONE NULL
);

CREATE INDEX idx_auth_webauthn_ceremony_expiry
    ON auth_webauthn_ceremonies(expires_at, used_at);

CREATE TABLE auth_webauthn_credentials (
    credential_hash CHAR(64) PRIMARY KEY,
    subject_uuid UUID NOT NULL,
    record_json TEXT NOT NULL,
    counter BIGINT NOT NULL,
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    last_used_at TIMESTAMP(6) WITHOUT TIME ZONE NULL
);

CREATE INDEX idx_auth_webauthn_subject
    ON auth_webauthn_credentials(subject_uuid);
