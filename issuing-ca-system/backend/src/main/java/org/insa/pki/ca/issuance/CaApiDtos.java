package org.insa.pki.ca.issuance;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public final class CaApiDtos {
    private CaApiDtos() {}

    public record IssueRequest(
            @NotBlank @Pattern(regexp = "[A-Fa-f0-9-]{36}") String requestId,
            @NotBlank @Size(max = 65_536) String csrPem,
            @NotBlank @Pattern(regexp = "tls-server|client-auth|code-signing") String profileName) {}

    public record IssueResponse(String requestId, String serialNumber, String certificatePem,
                                Instant issuedAt, Instant expiresAt, String status) {}

    public record RevokeRequest(
            @NotBlank @Pattern(regexp = "[A-Fa-f0-9-]{36}") String requestId,
            @NotBlank @Pattern(regexp = "(?i)[0-9a-f]{1,64}") String serialNumber,
            @NotBlank @Pattern(regexp = "keyCompromise|cACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|privilegeWithdrawn|aACompromise") String reason) {}

    public record RevokeResponse(String serialNumber, String status, String reason, Instant revokedAt) {}
}
