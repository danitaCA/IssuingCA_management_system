package org.insa.pki.ra.service;

import org.insa.pki.ra.api.ApiDtos.CsrSubmission;
import org.insa.pki.ra.domain.CertificateRequest;
import org.insa.pki.ra.domain.RequestStatus;
import org.insa.pki.ra.repository.CertificateRequestRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class RequestWorkflowService {
    private final CertificateRequestRepository requests;
    private final CsrParser csrParser;
    private final CertificateProfileService profiles;
    private final AuditService audit;

    public RequestWorkflowService(CertificateRequestRepository requests, CsrParser csrParser,
                                  CertificateProfileService profiles, AuditService audit) {
        this.requests = requests;
        this.csrParser = csrParser;
        this.profiles = profiles;
        this.audit = audit;
    }

    @Transactional
    public CertificateRequest submit(CsrSubmission body, String ownerId, String ip) {
        CsrParser.ParsedCsr parsed = csrParser.parseAndVerify(body.csrPem());
        profiles.validate(parsed, body.profileName());
        String sans = String.join("\n", parsed.sans());
        CertificateRequest request = requests.save(new CertificateRequest(UUID.randomUUID().toString(), ownerId,
                body.csrPem(), parsed.commonName(), sans, parsed.keyAlgorithm(), parsed.keySize(),
                parsed.signatureAlgorithm(), body.profileName()));
        audit.record(ownerId, ip, "CSR_SUBMIT", "CERTIFICATE_REQUEST", request.getId(),
                "CSR accepted for profile=" + body.profileName());
        return request;
    }

    @Transactional(readOnly = true)
    public CertificateRequest get(String id) {
        return requests.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Certificate request not found"));
    }

    @Transactional(readOnly = true)
    public Page<CertificateRequest> list(String ownerId, boolean canViewAll, RequestStatus status, Pageable pageable) {
        if (!canViewAll) return requests.findByOwnerId(ownerId, pageable);
        return status == null ? requests.findAll(pageable) : requests.findByStatus(status, pageable);
    }

    @Transactional
    public CertificateRequest approve(String id, String operatorId, String comment, String ip) {
        CertificateRequest request = get(id);
        requireStatus(request, RequestStatus.PENDING);
        request.setStatus(RequestStatus.APPROVED);
        request.setOperatorId(operatorId);
        request.setDecisionComment(comment);
        audit.record(operatorId, ip, "CSR_APPROVED", "CERTIFICATE_REQUEST", id, comment);
        return request;
    }

    @Transactional
    public CertificateRequest reject(String id, String operatorId, String comment, String ip) {
        CertificateRequest request = get(id);
        requireStatus(request, RequestStatus.PENDING);
        request.setStatus(RequestStatus.REJECTED);
        request.setOperatorId(operatorId);
        request.setDecisionComment(comment);
        audit.record(operatorId, ip, "CSR_REJECTED", "CERTIFICATE_REQUEST", id, comment);
        return request;
    }

    @Transactional
    public CaClient.IssuePayload markSubmittedToCa(String id, String ip) {
        CertificateRequest request = get(id);
        if (request.getStatus() == RequestStatus.APPROVED) {
            request.setStatus(RequestStatus.SUBMITTED_TO_CA);
            audit.record(request.getOperatorId(), ip, "CSR_SUBMITTED_TO_CA", "CERTIFICATE_REQUEST", id, "Issue request forwarded to CA");
        } else if (request.getStatus() != RequestStatus.SUBMITTED_TO_CA) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Request is not approved or awaiting CA retry");
        }
        return new CaClient.IssuePayload(request.getId(), request.getCsrPem(), request.getProfileName());
    }

    @Transactional
    public void markIssued(String id, String certificatePem, String serialNumber, String ip) {
        CertificateRequest request = get(id);
        requireStatus(request, RequestStatus.SUBMITTED_TO_CA);
        request.setCertificate(certificatePem, serialNumber);
        audit.record(request.getOperatorId(), ip, "CERTIFICATE_ISSUED", "CERTIFICATE_REQUEST", id, "Serial=" + serialNumber);
    }

    @Transactional
    public CertificateRequest markIssueFailed(String id, String ip) {
        CertificateRequest request = get(id);
        audit.record(request.getOperatorId(), ip, "CA_ISSUE_FAILED", "CERTIFICATE_REQUEST", id,
                "CA issue call failed; request retained for idempotent retry");
        return request;
    }

    @Transactional
    public CaClient.RevokePayload beginRevocation(String id, String operatorId, String reason, String comment, String ip) {
        CertificateRequest request = get(id);
        requireStatus(request, RequestStatus.ISSUED);
        request.setStatus(RequestStatus.REVOCATION_PENDING);
        request.setOperatorId(operatorId);
        request.setRevocationReason(reason);
        request.setDecisionComment(comment);
        audit.record(operatorId, ip, "REVOCATION_REQUESTED", "CERTIFICATE_REQUEST", id, "Reason=" + reason + "; " + comment);
        return new CaClient.RevokePayload(request.getId(), request.getSerialNumber(), reason);
    }

    @Transactional(readOnly = true)
    public CaClient.RevokePayload retryRevocation(String id) {
        CertificateRequest request = get(id);
        requireStatus(request, RequestStatus.REVOCATION_PENDING);
        return new CaClient.RevokePayload(request.getId(), request.getSerialNumber(), request.getRevocationReason());
    }

    @Transactional
    public CertificateRequest markRevoked(String id, String ip) {
        CertificateRequest request = get(id);
        requireStatus(request, RequestStatus.REVOCATION_PENDING);
        request.setStatus(RequestStatus.REVOKED);
        audit.record(request.getOperatorId(), ip, "CERTIFICATE_REVOKED", "CERTIFICATE_REQUEST", id,
                "Serial=" + request.getSerialNumber() + "; Reason=" + request.getRevocationReason());
        return request;
    }

    @Transactional
    public void markRevocationFailed(String id, String ip) {
        CertificateRequest request = get(id);
        audit.record(request.getOperatorId(), ip, "CA_REVOCATION_FAILED", "CERTIFICATE_REQUEST", id,
                "CA revocation call failed; request retained for retry");
    }

    private void requireStatus(CertificateRequest request, RequestStatus expected) {
        if (request.getStatus() != expected) throw new ResponseStatusException(HttpStatus.CONFLICT,
                "Expected request status " + expected + " but found " + request.getStatus());
    }
}
