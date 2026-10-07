package org.insa.pki.ca.audit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class CaAuditService {
    private final CaAuditEventRepository events;
    public CaAuditService(CaAuditEventRepository events) { this.events = events; }

    @Transactional
    public void record(String actor, String ip, String action, String targetId, String details) {
        String id = UUID.randomUUID().toString();
        Instant time = Instant.now();
        String content = String.join("|", id, time.toString(), safe(actor), safe(ip), action, safe(targetId), safe(details));
        try {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8)));
            events.save(new CaAuditEvent(id, time, actor, ip, action, targetId, details, hash));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to create CA audit event", exception);
        }
    }

    private String safe(String value) { return value == null ? "" : value; }
}
