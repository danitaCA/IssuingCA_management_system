                     # Issuing CA Management System

Enterprise-grade **Issuing Certificate Authority (CA)** system that provides secure digital certificate lifecycle management.

This backend implements the core requirements defined in the Software Requirements Specification (SRS), including:

- Certificate issuance, renewal, and revocation
- Registration Authority (RA) workflow
- CRL & OCSP validation services
- HSM-based private key protection
- Strong audit logging
- Role-based access control (RBAC)

---

## Technology Stack

| Layer              | Technology                          |
|--------------------|-------------------------------------|
| Language           | Java 21                             |
| Framework          | Spring Boot 3.3+                    |
| Architecture       | Modular Monolith + Hexagonal        |
| Database           | PostgreSQL / MariaDB                |
| Security           | Spring Security + RBAC + MFA        |
| Cryptography       | Bouncy Castle + PKCS#11 (HSM)       |
| API Documentation  | OpenAI 3 (Swagger)                 |
| Build Tool         | Maven (Multi-module)                |

---

## Project Structure   for   large enterprise Issuing CA system by  multiple module!

```text
pki-ca-backend/
├── pom.xml                          # Parent aggregator
├── README.md
├── .gitignore
├── docker-compose.yml               # PostgreSQL + SoftHSM (development)
│
├── common/                          # Shared library (no Spring Boot)
│   └── src/main/java/com/example/ca/common/
│       ├── domain/                  # Value objects & enums
│       │   ├── CertificateId.java
│       │   ├── SerialNumber.java
│       │   ├── DistinguishedName.java
│       │   ├── KeyAlgorithm.java
│       │   ├── SignatureAlgorithm.java
│       │   ├── CertificateStatus.java
│       │   ├── RevocationReason.java
│       │   └── CertificateProfileType.java
│       ├── crypto/
│       │   ├── CryptoProvider.java
│       │   └── PemUtils.java
│       ├── exception/
│       │   └── PkiException.java
│       └── security/
│           └── Roles.java
│
├── ca-core/                         # Main CA engine (Modular Monolith)
│   └── src/main/java/com/example/ca/core/
│       ├── CaCoreApplication.java
│       ├── domain/
│       │   ├── CertificateAuthority.java
│       │   ├── Certificate.java
│       │   ├── CertificateProfile.java
│       │   ├── CertificateRequest.java
│       │   ├── Crl.java
│       │   └── AuditEvent.java
│       ├── application/
│       │   ├── port/
│       │   │   ├── in/              # Use Cases
│       │   │   │   ├── IssueCertificateUseCase.java
│       │   │   │   ├── RevokeCertificateUseCase.java
│       │   │   │   ├── CreateCaUseCase.java
│       │   │   │   ├── ManageProfileUseCase.java
│       │   │   │   └── GetCertificateStatusUseCase.java
│       │   │   └── out/             # Outbound ports
│       │   │       ├── KeyStorePort.java
│       │   │       ├── CertificateRepositoryPort.java
│       │   │       ├── AuditPort.java
│       │   │       └── EventPublisherPort.java
│       │   └── service/
│       │       ├── IssueCertificateService.java
│       │       ├── RevokeCertificateService.java
│       │       ├── CaManagementService.java
│       │       └── ProfileService.java
│       ├── infrastructure/
│       │   ├── hsm/
│       │   │   ├── Pkcs11KeyStoreAdapter.java
│       │   │   └── SoftHsmAdapter.java
│       │   ├── persistence/
│       │   │   ├── entity/
│       │   │   ├── repository/
│       │   │   └── mapper/
│       │   ├── audit/
│       │   │   └── DatabaseAuditAdapter.java
│       │   └── messaging/
│       │       └── NoOpEventPublisher.java
│       ├── interfaces/
│       │   └── rest/
│       │       ├── CaController.java
│       │       ├── CertificateController.java
│       │       ├── ProfileController.java
│       │       ├── CrlController.java
│       │       └── dto/
│       └── config/
│           ├── SecurityConfig.java
│           ├── HsmConfig.java
│           └── OpenApiConfig.java
│
├── ocsp-service/                    # High-performance OCSP Responder
│   └── src/main/java/com/example/ca/ocsp/
│       ├── OcspServiceApplication.java
│       └── OcspResponderService.java
│
└── docs/
    ├── architecture.md
    └── Api/
        └── openapi.yaml
    High-Level Architecture

'''text

┌─────────────────┐       ┌──────────────────────┐       ┌─────────────────┐
│   RA Portal /   │       │                      │       │                 │
│   Admin UI      │──────▶│      ca-core         │◀──────│   HSM (PKCS#11) │
└─────────────────┘       │ (Issuing CA Engine) │       └─────────────────┘
                          │                      │
                          │ • Certificate Mgmt  │
                          │ • Lifecycle         │
                          │ • Profiles          │
                          │ • Audit             │
                          └──────────┬───────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
             ┌────────────┐   ┌────────────┐   ┌────────────┐
             │ ocsp-service│   │ CRL Service│   │ Database │
             │ (RFC 6960) │   │            │   │            │
             └────────────┘   └────────────┘   └────────────┘


                  ##   Certificate Lifecycle Workflow
    ## 1. Certificate Issuance Flow
1. User / System generates Key Pair + CSR
2. CSR is submitted to the Registration Authority (RA)
3. RA Operator verifies the identity and approves the request
4. Approved CSR is sent to ca-core
5. ca-core validates the CSR against the selected Certificate Profile
6. The Issuing CA private key (protected inside HSM) signs the certificate
7. X.509 certificate is generated and persisted
8. Audit event is recorded
9. Certificate is returned to the requester
       2. Certificate Revocation Flow
1. Authorized operator requests revocation (reason is mandatory)
2. ca-core updates the certificate status to REVOKED
3. CRL is regenerated / updated
4. OCSP service reflects the new status
5. Audit event is recorded
          3. Certificate Validation Flow (OCSP)
text
Client → OCSP Request → ocsp-service → Checks current status → Signed OCSP Response!!!
