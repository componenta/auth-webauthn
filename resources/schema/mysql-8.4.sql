CREATE TABLE auth_webauthn_ceremonies (
    uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    binding_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    options_json LONGTEXT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    INDEX idx_auth_webauthn_ceremony_expiry (expires_at, used_at)
) ENGINE=InnoDB;

CREATE TABLE auth_webauthn_credentials (
    credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record_json LONGTEXT NOT NULL,
    counter BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    last_used_at DATETIME(6) NULL,
    INDEX idx_auth_webauthn_subject (subject_uuid)
) ENGINE=InnoDB;
