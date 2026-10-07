package org.insa.pki.ra.domain;

public enum RequestStatus {
    PENDING,
    APPROVED,
    REJECTED,
    SUBMITTED_TO_CA,
    ISSUED,
    REVOCATION_PENDING,
    REVOKED
}
