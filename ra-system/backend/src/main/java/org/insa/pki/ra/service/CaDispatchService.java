package org.insa.pki.ra.service;

import org.insa.pki.ra.domain.CertificateRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CaDispatchService {
    private final CaClient caClient;
    private final RequestWorkflowService workflow;
    private final CsrParser csrParser;

    public CaDispatchService(CaClient caClient, RequestWorkflowService workflow, CsrParser csrParser) {
        this.caClient = caClient;
        this.workflow = workflow;
        this.csrParser = csrParser;
    }

    public CertificateRequest issue(String id, String ip) {
        CaClient.IssuePayload payload = workflow.markSubmittedToCa(id, ip);
        try {
            CaClient.IssueResult result = caClient.issue(payload);
            CsrParser.ParsedCsr parsed = csrParser.parseAndVerify(payload.csrPem());
            String serial = csrParser.serialNumber(result.certificatePem(), parsed);
            workflow.markIssued(id, result.certificatePem(), serial, ip);
            return workflow.get(id);
        } catch (RuntimeException exception) {
            workflow.markIssueFailed(id, ip);
            if (exception instanceof ResponseStatusException statusException && statusException.getStatusCode().value() == 502) {
                throw statusException;
            }
            if (exception instanceof RestClientException) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Issuing CA is unavailable; request is retained for retry");
            }
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Issuing CA response could not be validated; request is retained for retry");
        }
    }

    public CertificateRequest revoke(String id, String operatorId, String reason, String comment, String ip) {
        CaClient.RevokePayload payload = workflow.beginRevocation(id, operatorId, reason, comment, ip);
        return sendRevocation(id, payload, ip);
    }

    public CertificateRequest retryRevocation(String id, String ip) {
        return sendRevocation(id, workflow.retryRevocation(id), ip);
    }

    private CertificateRequest sendRevocation(String id, CaClient.RevokePayload payload, String ip) {
        try {
            caClient.revoke(payload);
            return workflow.markRevoked(id, ip);
        } catch (RuntimeException exception) {
            workflow.markRevocationFailed(id, ip);
            if (exception instanceof RestClientException) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Issuing CA is unavailable; revocation remains pending for retry");
            }
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CA revocation failed; revocation remains pending for retry");
        }
    }
}
