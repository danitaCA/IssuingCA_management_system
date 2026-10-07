package org.insa.pki.ra.service;

import org.insa.pki.ra.domain.AuditEvent;
import org.insa.pki.ra.repository.AuditEventRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class AuditService {
    private final AuditEventRepository repository;
    public AuditService(AuditEventRepository repository) { this.repository = repository; }

    @Transactional
    public void record(String actorId, String ip, String action, String targetType, String targetId, String details) {
        Instant now = Instant.now();
        String id = UUID.randomUUID().toString();
        String canonical = String.join("|", id, now.toString(), safe(actorId), safe(ip), safe(action),
                safe(targetType), safe(targetId), safe(details));
        repository.save(new AuditEvent(id, now, actorId, ip, action, targetType, targetId, details, sha256(canonical)));
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> list(Pageable pageable) { return repository.findAllByOrderByOccurredAtDesc(pageable); }

    private String safe(String value) { return value == null ? "" : value; }
    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception exception) { throw new IllegalStateException("SHA-256 is unavailable", exception); }
    }
}
