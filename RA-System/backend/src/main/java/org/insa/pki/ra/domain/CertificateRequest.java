package org.insa.pki.ra.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "certificate_request", indexes = {
        @Index(name = "idx_request_status_created", columnList = "status, created_at"),
        @Index(name = "idx_request_owner_created", columnList = "owner_id, created_at")
})
public class CertificateRequest {
    @Id
    @Column(length = 36, nullable = false)
    private String id;
    @Column(name = "owner_id", nullable = false, length = 36)
    private String ownerId;
    @Lob
    @Column(name = "csr_pem", nullable = false, columnDefinition = "MEDIUMTEXT")
    private String csrPem;
    @Column(name = "common_name", nullable = false)
    private String commonName;
    @Column(name = "subject_alt_names", columnDefinition = "TEXT")
    private String subjectAltNames;
    @Column(name = "key_algorithm", nullable = false, length = 32)
    private String keyAlgorithm;
    @Column(name = "key_size", nullable = false)
    private int keySize;
    @Column(name = "signature_algorithm", nullable = false, length = 128)
    private String signatureAlgorithm;
    @Column(name = "profile_name", nullable = false, length = 80)
    private String profileName;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private RequestStatus status;
    @Lob
    @Column(name = "certificate_pem", columnDefinition = "MEDIUMTEXT")
    private String certificatePem;
    @Column(name = "serial_number", length = 128)
    private String serialNumber;
    @Column(name = "operator_id", length = 36)
    private String operatorId;
    @Column(name = "decision_comment", length = 2000)
    private String decisionComment;
    @Column(name = "revocation_reason", length = 64)
    private String revocationReason;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
    @Column(name = "issued_at")
    private Instant issuedAt;
    @Version
    private long version;

    protected CertificateRequest() {}

    public CertificateRequest(String id, String ownerId, String csrPem, String commonName,
                              String subjectAltNames, String keyAlgorithm, int keySize,
                              String signatureAlgorithm, String profileName) {
        this.id = id;
        this.ownerId = ownerId;
        this.csrPem = csrPem;
        this.commonName = commonName;
        this.subjectAltNames = subjectAltNames;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.signatureAlgorithm = signatureAlgorithm;
        this.profileName = profileName;
        this.status = RequestStatus.PENDING;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    @PreUpdate
    void touch() { updatedAt = Instant.now(); }

    public String getId() { return id; }
    public String getOwnerId() { return ownerId; }
    public String getCsrPem() { return csrPem; }
    public String getCommonName() { return commonName; }
    public String getSubjectAltNames() { return subjectAltNames; }
    public String getKeyAlgorithm() { return keyAlgorithm; }
    public int getKeySize() { return keySize; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public String getProfileName() { return profileName; }
    public RequestStatus getStatus() { return status; }
    public String getCertificatePem() { return certificatePem; }
    public String getSerialNumber() { return serialNumber; }
    public String getOperatorId() { return operatorId; }
    public String getDecisionComment() { return decisionComment; }
    public String getRevocationReason() { return revocationReason; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Instant getIssuedAt() { return issuedAt; }
    public void setStatus(RequestStatus status) { this.status = status; }
    public void setOperatorId(String operatorId) { this.operatorId = operatorId; }
    public void setDecisionComment(String decisionComment) { this.decisionComment = decisionComment; }
    public void setCertificate(String certificatePem, String serialNumber) {
        this.certificatePem = certificatePem;
        this.serialNumber = serialNumber;
        this.issuedAt = Instant.now();
        this.status = RequestStatus.ISSUED;
    }
    public void setRevocationReason(String revocationReason) { this.revocationReason = revocationReason; }
}
