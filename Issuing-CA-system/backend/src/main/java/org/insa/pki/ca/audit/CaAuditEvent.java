package org.insa.pki.ca.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "ca_audit_event")
public class CaAuditEvent {
    @Id
    @Column(length = 36, nullable = false)
    private String id;
    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;
    @Column(name = "actor_subject", length = 512)
    private String actorSubject;
    @Column(name = "client_ip", length = 45)
    private String clientIp;
    @Column(nullable = false, length = 80)
    private String action;
    @Column(name = "target_id", length = 100)
    private String targetId;
    @Column(length = 2000)
    private String details;
    @Column(name = "content_hash", nullable = false, length = 64)
    private String contentHash;

    protected CaAuditEvent() {}
    public CaAuditEvent(String id, Instant occurredAt, String actorSubject, String clientIp,
                        String action, String targetId, String details, String contentHash) {
        this.id = id;
        this.occurredAt = occurredAt;
        this.actorSubject = actorSubject;
        this.clientIp = clientIp;
        this.action = action;
        this.targetId = targetId;
        this.details = details;
        this.contentHash = contentHash;
    }
}


