package org.insa.pki.ca.issuance;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.insa.pki.ca.crl.CrlService;
import org.insa.pki.ca.profiles.CertificateProfile;
import org.insa.pki.ca.revocation.CaRevocationService;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class CaController {
    private final CaCertificateService certificates;
    private final CaRevocationService revocations;
    private final CrlService crls;

    public CaController(CaCertificateService certificates, CaRevocationService revocations, CrlService crls) {
        this.certificates = certificates;
        this.revocations = revocations;
        this.crls = crls;
    }

    @PostMapping("/certificates/issue")
    @ResponseStatus(HttpStatus.CREATED)
    public CaApiDtos.IssueResponse issue(@Valid @RequestBody CaApiDtos.IssueRequest body,
                                          Authentication authentication, HttpServletRequest request) {
        return certificates.issue(body, authentication == null ? null : authentication.getName(), request.getRemoteAddr());
    }

    @PostMapping("/certificates/revoke")
    public CaApiDtos.RevokeResponse revoke(@Valid @RequestBody CaApiDtos.RevokeRequest body,
                                            Authentication authentication, HttpServletRequest request) {
        return revocations.revoke(body, authentication == null ? null : authentication.getName(), request.getRemoteAddr());
    }

    @GetMapping("/profiles")
    public List<CertificateProfile> profiles() { return certificates.listProfiles(); }

    @GetMapping(value = "/crl", produces = "application/pkix-crl")
    public ResponseEntity<byte[]> crl() {
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/pkix-crl"))
                .cacheControl(CacheControl.noCache()).header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=issuing-ca.crl")
                .body(crls.generate());
    }
}
