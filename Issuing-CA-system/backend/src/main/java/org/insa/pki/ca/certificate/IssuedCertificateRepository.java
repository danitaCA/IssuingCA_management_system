package org.insa.pki.ca.certificate;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface IssuedCertificateRepository extends JpaRepository<IssuedCertificate, String> {
    Optional<IssuedCertificate> findByRequestId(String requestId);
    Optional<IssuedCertificate> findBySerialNumber(String serialNumber);
    List<IssuedCertificate> findByRevokedAtIsNotNull();
}
