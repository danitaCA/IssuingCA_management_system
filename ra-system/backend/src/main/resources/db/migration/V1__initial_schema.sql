CREATE TABLE app_user (
    id CHAR(36) NOT NULL PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    role VARCHAR(32) NOT NULL,
    totp_secret VARCHAR(128) NULL,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;

CREATE TABLE certificate_request (
    id CHAR(36) NOT NULL PRIMARY KEY,
    owner_id CHAR(36) NOT NULL,
    csr_pem MEDIUMTEXT NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    subject_alt_names TEXT NULL,
    key_algorithm VARCHAR(32) NOT NULL,
    key_size INT NOT NULL,
    signature_algorithm VARCHAR(128) NOT NULL,
    profile_name VARCHAR(80) NOT NULL,
    status VARCHAR(32) NOT NULL,
    certificate_pem MEDIUMTEXT NULL,
    serial_number VARCHAR(128) NULL,
    operator_id CHAR(36) NULL,
    decision_comment VARCHAR(2000) NULL,
    revocation_reason VARCHAR(64) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    issued_at TIMESTAMP(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT fk_request_owner FOREIGN KEY (owner_id) REFERENCES app_user(id),
    CONSTRAINT fk_request_operator FOREIGN KEY (operator_id) REFERENCES app_user(id),
    INDEX idx_request_status_created (status, created_at),
    INDEX idx_request_owner_created (owner_id, created_at),
    INDEX idx_request_serial (serial_number)
) ENGINE=InnoDB;

CREATE TABLE audit_event (
    id CHAR(36) NOT NULL PRIMARY KEY,
    occurred_at TIMESTAMP(6) NOT NULL,
    actor_id CHAR(36) NULL,
    ip_address VARCHAR(45) NULL,
    action VARCHAR(80) NOT NULL,
    target_type VARCHAR(80) NOT NULL,
    target_id VARCHAR(100) NULL,
    details VARCHAR(2000) NULL,
    content_hash CHAR(64) NOT NULL,
    INDEX idx_audit_occurred (occurred_at),
    INDEX idx_audit_actor (actor_id, occurred_at),
    INDEX idx_audit_target (target_type, target_id)
) ENGINE=InnoDB;

-- Keep application audit entries append-only. DB administrators remain trusted;
-- forward these records to a separately administered immutable SIEM/log store.
DELIMITER //
CREATE TRIGGER audit_event_no_update BEFORE UPDATE ON audit_event FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_event is append-only';
END//
CREATE TRIGGER audit_event_no_delete BEFORE DELETE ON audit_event FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_event is append-only';
END//
DELIMITER ;
