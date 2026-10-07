package org.insa.pki.ca.revocation;

import org.insa.pki.ca.audit.CaAuditService;
import org.insa.pki.ca.certificate.IssuedCertificate;
import org.insa.pki.ca.certificate.IssuedCertificateRepository;
import org.insa.pki.ca.issuance.CaApiDtos;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.Locale;

@Service
public class CaRevocationService {
    private final IssuedCertificateRepository certificates;
    private final CaAuditService audit;
    public CaRevocationService(IssuedCertificateRepository certificates, CaAuditService audit) {
        this.certificates = certificates;
        this.audit = audit;
    }

    @Transactional
    public CaApiDtos.RevokeResponse revoke(CaApiDtos.RevokeRequest request, String actor, String ip) {
        String serial = request.serialNumber().toUpperCase(Locale.ROOT);
        IssuedCertificate certificate = certificates.findByRequestId(request.requestId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Certificate request ID is unknown"));
        if (!certificate.getSerialNumber().equalsIgnoreCase(serial)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Serial number does not belong to the supplied request ID");
        }
        if (certificate.getRevokedAt() == null) {
            certificate.revoke(request.reason());
            audit.record(actor, ip, "CERTIFICATE_REVOKED", serial, "Reason=" + request.reason());
        }
        return new CaApiDtos.RevokeResponse(serial, "REVOKED", certificate.getRevocationReason(), certificate.getRevokedAt());
    }

    @Transactional(readOnly = true)
    public java.util.List<IssuedCertificate> revokedCertificates() { return certificates.findByRevokedAtIsNotNull(); }
}
