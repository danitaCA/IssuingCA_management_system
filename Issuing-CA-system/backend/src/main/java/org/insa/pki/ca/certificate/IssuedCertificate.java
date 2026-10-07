package org.insa.pki.ca.certificate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import java.time.Instant;

@Entity
@Table(name = "issued_certificate", uniqueConstraints = {
        @UniqueConstraint(name = "uk_issued_certificate_request", columnNames = "request_id"),
        @UniqueConstraint(name = "uk_issued_certificate_serial", columnNames = "serial_number")
})
public class IssuedCertificate {
    @Id
    @Column(length = 36, nullable = false)
    private String id;
    @Column(name = "request_id", nullable = false, length = 36)
    private String requestId;
    @Column(name = "serial_number", nullable = false, length = 64)
    private String serialNumber;
    @Column(name = "subject_dn", nullable = false, length = 2048)
    private String subjectDn;
    @Column(name = "profile_name", nullable = false, length = 80)
    private String profileName;
    @Column(name = "request_fingerprint", nullable = false, length = 64)
    private String requestFingerprint;
    @Lob
    @Column(name = "certificate_pem", nullable = false, columnDefinition = "MEDIUMTEXT")
    private String certificatePem;
    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    @Column(name = "revoked_at")
    private Instant revokedAt;
    @Column(name = "revocation_reason", length = 40)
    private String revocationReason;
    @Version
    private long version;

    protected IssuedCertificate() {}

    public IssuedCertificate(String id, String requestId, String serialNumber, String subjectDn,
                             String profileName, String requestFingerprint, String certificatePem,
                             Instant issuedAt, Instant expiresAt) {
        this.id = id;
        this.requestId = requestId;
        this.serialNumber = serialNumber;
        this.subjectDn = subjectDn;
        this.profileName = profileName;
        this.requestFingerprint = requestFingerprint;
        this.certificatePem = certificatePem;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public void revoke(String reason) {
        if (revokedAt == null) {
            revokedAt = Instant.now();
            revocationReason = reason;
        }
    }

    @PreUpdate
    void touch() { }

    public String getId() { return id; }
    public String getRequestId() { return requestId; }
    public String getSerialNumber() { return serialNumber; }
    public String getSubjectDn() { return subjectDn; }
    public String getProfileName() { return profileName; }
    public String getRequestFingerprint() { return requestFingerprint; }
    public String getCertificatePem() { return certificatePem; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getRevocationReason() { return revocationReason; }
}
