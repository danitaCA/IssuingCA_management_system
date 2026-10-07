package org.insa.pki.ra.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.insa.pki.ra.api.ApiDtos.*;
import org.insa.pki.ra.domain.CertificateRequest;
import org.insa.pki.ra.domain.RequestStatus;
import org.insa.pki.ra.service.CaDispatchService;
import org.insa.pki.ra.service.RequestWorkflowService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class RequestController {
    private final RequestWorkflowService workflow;
    private final CaDispatchService caDispatch;

    public RequestController(RequestWorkflowService workflow, CaDispatchService caDispatch) {
        this.workflow = workflow;
        this.caDispatch = caDispatch;
    }

    @PostMapping("/requests")
    @ResponseStatus(HttpStatus.CREATED)
    public CertificateRequestResponse submit(@Valid @RequestBody CsrSubmission body,
                                             Authentication authentication, HttpServletRequest request) {
        return CertificateRequestResponse.from(workflow.submit(body, authentication.getName(), request.getRemoteAddr()));
    }

    @GetMapping("/requests")
    public Page<CertificateRequestResponse> list(@RequestParam(required = false) RequestStatus status,
                                                  @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
                                                  Authentication authentication) {
        return workflow.list(authentication.getName(), canViewAll(authentication), status, pageable)
                .map(CertificateRequestResponse::from);
    }

    @GetMapping("/requests/{id}")
    public CertificateRequestResponse get(@PathVariable String id, Authentication authentication) {
        CertificateRequest item = workflow.get(id);
        if (!item.getOwnerId().equals(authentication.getName()) && !canViewAll(authentication)) {
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND, "Certificate request not found");
        }
        return CertificateRequestResponse.from(item);
    }

    @PostMapping("/requests/{id}/approve")
    public CertificateRequestResponse approve(@PathVariable String id, @Valid @RequestBody DecisionRequest body,
                                              Authentication authentication, HttpServletRequest request) {
        workflow.approve(id, authentication.getName(), body.comment(), request.getRemoteAddr());
        return CertificateRequestResponse.from(caDispatch.issue(id, request.getRemoteAddr()));
    }

    @PostMapping("/requests/{id}/reject")
    public CertificateRequestResponse reject(@PathVariable String id, @Valid @RequestBody DecisionRequest body,
                                              Authentication authentication, HttpServletRequest request) {
        return CertificateRequestResponse.from(workflow.reject(id, authentication.getName(), body.comment(), request.getRemoteAddr()));
    }

    @PostMapping("/requests/{id}/retry-ca")
    public CertificateRequestResponse retryCa(@PathVariable String id, Authentication authentication,
                                               HttpServletRequest request) {
        return CertificateRequestResponse.from(caDispatch.issue(id, request.getRemoteAddr()));
    }

    @PostMapping("/certificates/{requestId}/revoke")
    public CertificateRequestResponse revoke(@PathVariable String requestId, @Valid @RequestBody RevocationRequest body,
                                              Authentication authentication, HttpServletRequest request) {
        return CertificateRequestResponse.from(caDispatch.revoke(requestId, authentication.getName(), body.reason(),
                body.comment(), request.getRemoteAddr()));
    }

    @PostMapping("/certificates/{requestId}/retry-revoke")
    public CertificateRequestResponse retryRevoke(@PathVariable String requestId, HttpServletRequest request) {
        return CertificateRequestResponse.from(caDispatch.retryRevocation(requestId, request.getRemoteAddr()));
    }

    private boolean canViewAll(Authentication authentication) {
        return authentication.getAuthorities().stream().anyMatch(authority -> switch (authority.getAuthority()) {
            case "ROLE_OPERATOR", "ROLE_ADMIN", "ROLE_AUDITOR", "ROLE_CA_ADMIN" -> true;
            default -> false;
        });
    }
}
