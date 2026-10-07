package org.insa.pki.ra.repository;

import org.insa.pki.ra.domain.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AuditEventRepository extends JpaRepository<AuditEvent, String> {
    Page<AuditEvent> findAllByOrderByOccurredAtDesc(Pageable pageable);
}
