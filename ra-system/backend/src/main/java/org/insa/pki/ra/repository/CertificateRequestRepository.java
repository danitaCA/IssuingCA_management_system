package org.insa.pki.ra.repository;

import org.insa.pki.ra.domain.CertificateRequest;
import org.insa.pki.ra.domain.RequestStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRequestRepository extends JpaRepository<CertificateRequest, String> {
    Page<CertificateRequest> findByOwnerId(String ownerId, Pageable pageable);
    Page<CertificateRequest> findByStatus(RequestStatus status, Pageable pageable);
}
