package org.insa.pki.ca.audit;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CaAuditEventRepository extends JpaRepository<CaAuditEvent, String> {}
