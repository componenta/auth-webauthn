ALTER TABLE auth_webauthn_credentials
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 0;
