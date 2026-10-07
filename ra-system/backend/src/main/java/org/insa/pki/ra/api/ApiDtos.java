package org.insa.pki.ra.api;

import jakarta.validation.constraints.*;
import org.insa.pki.ra.domain.*;
import java.time.Instant;
import java.util.List;

public final class ApiDtos {
    private ApiDtos() {}

    public record RegisterRequest(
            @NotBlank @Size(min = 3, max = 80) @Pattern(regexp = "[A-Za-z0-9._-]+") String username,
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(min = 12, max = 72) String password) {}

    public record LoginRequest(@NotBlank String username, @NotBlank String password,
                               @Pattern(regexp = "[0-9]{6}") String otp) {}
    public record TokenResponse(String accessToken, String tokenType, long expiresInSeconds) {}
    public record MfaSetupRequest(@NotBlank String username, @NotBlank String password) {}
    public record MfaSetupResponse(String secret, String otpauthUri) {}
    public record MfaEnableRequest(@NotBlank String username, @NotBlank String password,
                                   @NotBlank @Pattern(regexp = "[0-9]{6}") String otp) {}
    public record CreateUserRequest(@NotBlank @Size(min = 3, max = 80) @Pattern(regexp = "[A-Za-z0-9._-]+") String username,
                                    @NotBlank @Email @Size(max = 254) String email,
                                    @NotBlank @Size(min = 12, max = 72) String password,
                                    @NotNull Role role) {}
    public record UserResponse(String id, String username, String email, Role role, boolean enabled, Instant createdAt) {
        public static UserResponse from(AppUser user) {
            return new UserResponse(user.getId(), user.getUsername(), user.getEmail(), user.getRole(), user.isEnabled(), user.getCreatedAt());
        }
    }
    public record EnabledRequest(@NotNull Boolean enabled) {}
    public record CsrSubmission(@NotBlank @Size(max = 65536) String csrPem,
                                @NotBlank @Size(max = 80) String profileName) {}
    public record DecisionRequest(@NotBlank @Size(min = 5, max = 2000) String comment) {}
    public record RevocationRequest(@NotBlank @Pattern(regexp = "keyCompromise|cACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|privilegeWithdrawn|aACompromise") String reason,
                                    @NotBlank @Size(min = 5, max = 2000) String comment) {}
    public record CertificateRequestResponse(String id, String ownerId, String commonName, List<String> subjectAltNames,
                                             String keyAlgorithm, int keySize, String signatureAlgorithm,
                                             String profileName, RequestStatus status, String certificatePem,
                                             String serialNumber, String operatorId, String decisionComment,
                                             String revocationReason, Instant createdAt, Instant updatedAt, Instant issuedAt) {
        public static CertificateRequestResponse from(CertificateRequest request) {
            List<String> sans = request.getSubjectAltNames() == null || request.getSubjectAltNames().isBlank()
                    ? List.of() : List.of(request.getSubjectAltNames().split("\\n"));
            return new CertificateRequestResponse(request.getId(), request.getOwnerId(), request.getCommonName(), sans,
                    request.getKeyAlgorithm(), request.getKeySize(), request.getSignatureAlgorithm(), request.getProfileName(),
                    request.getStatus(), request.getCertificatePem(), request.getSerialNumber(), request.getOperatorId(),
                    request.getDecisionComment(), request.getRevocationReason(), request.getCreatedAt(), request.getUpdatedAt(), request.getIssuedAt());
        }
    }
    public record CertificateProfile(String name, String description, List<String> keyAlgorithms,
                                     List<Integer> keySizes, List<String> extendedKeyUsages) {}
    public record AuditResponse(String id, Instant occurredAt, String actorId, String ipAddress,
                                String action, String targetType, String targetId, String details, String contentHash) {
        public static AuditResponse from(AuditEvent event) {
            return new AuditResponse(event.getId(), event.getOccurredAt(), event.getActorId(), event.getIpAddress(),
                    event.getAction(), event.getTargetType(), event.getTargetId(), event.getDetails(), event.getContentHash());
        }
    }
    public record ApiError(Instant timestamp, int status, String error, String message, String path) {}
}
