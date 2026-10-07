package org.insa.pki.ca.revocation;

import org.insa.pki.ca.audit.CaAuditService;
import org.insa.pki.ca.certificate.IssuedCertificate;
import org.insa.pki.ca.certificate.IssuedCertificateRepository;
import org.insa.pki.ca.issuance.CaApiDtos;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CaRevocationServiceTest {
    @Test
    void revokesOnlyTheMatchingRequestAndSerialAndIsIdempotent() {
        String requestId = "31ff071b-ffbb-4562-b9de-bd419263e979";
        IssuedCertificate certificate = new IssuedCertificate("id", requestId, "A1B2C3",
                "CN=host.example.org", "tls-server", "fingerprint", "PEM",
                Instant.now(), Instant.now().plusSeconds(3600));
        IssuedCertificateRepository repository = mock(IssuedCertificateRepository.class);
        CaAuditService audit = mock(CaAuditService.class);
        when(repository.findByRequestId(requestId)).thenReturn(Optional.of(certificate));
        CaRevocationService service = new CaRevocationService(repository, audit);
        var request = new CaApiDtos.RevokeRequest(requestId, "a1b2c3", "keyCompromise");

        var first = service.revoke(request, "CN=ra-client", "127.0.0.1");
        var second = service.revoke(request, "CN=ra-client", "127.0.0.1");

        assertEquals("REVOKED", first.status());
        assertEquals("keyCompromise", second.reason());
        assertNotNull(second.revokedAt());
        verify(audit, times(1)).record("CN=ra-client", "127.0.0.1", "CERTIFICATE_REVOKED",
                "A1B2C3", "Reason=keyCompromise");
    }

    @Test
    void rejectsSerialThatDoesNotMatchRequest() {
        String requestId = "31ff071b-ffbb-4562-b9de-bd419263e979";
        IssuedCertificate certificate = new IssuedCertificate("id", requestId, "A1B2C3",
                "CN=host.example.org", "tls-server", "fingerprint", "PEM",
                Instant.now(), Instant.now().plusSeconds(3600));
        IssuedCertificateRepository repository = mock(IssuedCertificateRepository.class);
        when(repository.findByRequestId(requestId)).thenReturn(Optional.of(certificate));
        CaRevocationService service = new CaRevocationService(repository, mock(CaAuditService.class));

        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> service.revoke(new CaApiDtos.RevokeRequest(requestId, "DEADBEEF", "keyCompromise"),
                        "CN=ra-client", "127.0.0.1"));
    }
}
