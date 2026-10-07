package org.insa.pki.ra.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_event")
public class AuditEvent {
    @Id
    @Column(length = 36, nullable = false)
    private String id;
    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;
    @Column(name = "actor_id", length = 36)
    private String actorId;
    @Column(name = "ip_address", length = 45)
    private String ipAddress;
    @Column(nullable = false, length = 80)
    private String action;
    @Column(name = "target_type", nullable = false, length = 80)
    private String targetType;
    @Column(name = "target_id", length = 100)
    private String targetId;
    @Column(length = 2000)
    private String details;
    @Column(name = "content_hash", nullable = false, length = 64)
    private String contentHash;

    protected AuditEvent() {}
    public AuditEvent(String id, Instant occurredAt, String actorId, String ipAddress,
                      String action, String targetType, String targetId, String details, String contentHash) {
        this.id = id;
        this.occurredAt = occurredAt;
        this.actorId = actorId;
        this.ipAddress = ipAddress;
        this.action = action;
        this.targetType = targetType;
        this.targetId = targetId;
        this.details = details;
        this.contentHash = contentHash;
    }
    public String getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getActorId() { return actorId; }
    public String getIpAddress() { return ipAddress; }
    public String getAction() { return action; }
    public String getTargetType() { return targetType; }
    public String getTargetId() { return targetId; }
    public String getDetails() { return details; }
    public String getContentHash() { return contentHash; }
}
