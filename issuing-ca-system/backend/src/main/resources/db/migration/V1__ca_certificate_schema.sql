CREATE TABLE issued_certificate (
    id CHAR(36) NOT NULL PRIMARY KEY,
    request_id CHAR(36) NOT NULL,
    serial_number VARCHAR(64) NOT NULL,
    subject_dn VARCHAR(2048) NOT NULL,
    profile_name VARCHAR(80) NOT NULL,
    request_fingerprint CHAR(64) NOT NULL,
    certificate_pem MEDIUMTEXT NOT NULL,
    issued_at TIMESTAMP(6) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    revoked_at TIMESTAMP(6) NULL,
    revocation_reason VARCHAR(40) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_issued_certificate_request UNIQUE (request_id),
    CONSTRAINT uk_issued_certificate_serial UNIQUE (serial_number),
    INDEX idx_issued_expiry (expires_at),
    INDEX idx_issued_revocation (revoked_at)
) ENGINE=InnoDB;

CREATE TABLE ca_audit_event (
    id CHAR(36) NOT NULL PRIMARY KEY,
    occurred_at TIMESTAMP(6) NOT NULL,
    actor_subject VARCHAR(512) NULL,
    client_ip VARCHAR(45) NULL,
    action VARCHAR(80) NOT NULL,
    target_id VARCHAR(100) NULL,
    details VARCHAR(2000) NULL,
    content_hash CHAR(64) NOT NULL,
    INDEX idx_ca_audit_time (occurred_at),
    INDEX idx_ca_audit_target (target_id)
) ENGINE=InnoDB;

CREATE TRIGGER ca_audit_no_update BEFORE UPDATE ON ca_audit_event
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'CA audit events are append-only';
CREATE TRIGGER ca_audit_no_delete BEFORE DELETE ON ca_audit_event
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'CA audit events are append-only';
