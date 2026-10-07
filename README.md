# PKI Issuing Platform

## Enterprise Registration Authority (RA) and Issuing Certificate Authority (CA)

PKI Issuing Platform is a security-focused, enterprise-style Public Key Infrastructure (PKI) issuing platform composed of two independently managed but securely integrated subsystems:

* **Registration Authority (RA)** — responsible for identity registration, authentication, authorization, CSR submission and validation, approval workflows, certificate lifecycle requests, and audit operations.
* **Issuing Certificate Authority (CA)** — responsible for cryptographic certificate issuance, signing, revocation, CRL generation, and protected CA private-key operations through PKCS#11/HSM integration.

The architecture intentionally separates RA and CA responsibilities to establish a strong **security and trust boundary**. The RA does not directly access CA private keys. Certificate issuance requests are transferred from the RA to the CA through authenticated and authorized service-to-service communication.

The repository is currently **backend-only**. Frontend applications are intentionally excluded from this repository.
1. Architecture Overview
                         ┌──────────────────────────────┐
                         │        RA System             │
                         │                              │
                         │  Authentication / MFA        │
                         │  RBAC                        │
                         │  Entity Registration          │
                         │  CSR Submission              │
                         │  CSR Validation              │
                         │  Approval Workflow           │
                         │  Certificate Tracking        │
                         │  Revocation Requests         │
                         │  Audit Logging               │
                         └──────────────┬───────────────┘
                                        │
                              Authenticated & Authorized
                                   mTLS Service API
                                        │
                                        ▼
                         ┌──────────────────────────────┐
                         │        Issuing CA            │
                         │                              │
                         │  PKCS#10 Validation          │
                         │  Certificate Profiles        │
                         │  Certificate Issuance         │
                         │  Certificate Revocation      │
                         │  CRL Generation              │
                         │  CA Audit Records            │
                         │                              │
                         │       PKCS#11 Boundary       │
                         └──────────────┬───────────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │    HSM / PKCS#11    │
                              │                     │
                              │  CA Private Keys    │
                              │  Signing Operations │
                              └─────────────────────┘

The RA and CA are therefore **separate applications with independent security boundaries**, while the integration layer allows them to operate together as one enterprise issuing platform.


# 2. Security Architecture Principles

The platform follows these core security principles:

### Separation of Duties

RA and CA responsibilities are separated.

The RA handles registration and authorization workflows, while the CA performs cryptographic certificate issuance.

### Protection of CA Private Keys

CA private keys must not be stored in the application database, source code, configuration files, or filesystem.

Production signing operations are designed around a **PKCS#11-compatible Hardware Security Module (HSM)**.

### Zero Trust Service Communication

RA-to-CA communication must use authenticated service-to-service communication.

Production integration requires **mutual TLS (mTLS)** and explicit authorization of the calling service.

### Least Privilege

Users, services, database accounts, and HSM identities should receive only the permissions required for their responsibilities.

### Role-Based Access Control

Privileged operations are protected through RBAC and additional authentication controls.

### Strong Authentication

Privileged RA users use short-lived bearer authentication and TOTP-based MFA.

### Cryptographic Verification

Certificate Signing Requests are cryptographically verified before certificate issuance.

### Auditability

Security-sensitive operations generate append-only audit records to support investigation, accountability, and compliance.

### Secure Configuration

Secrets, passwords, private credentials, HSM configuration, and TLS materials must never be committed to source control.

# 3. Repository Structure
KI-Issuing-Platform/
│
├── ra-system/
│   ├── backend/
│   │   ├── src/
│   │   ├── pom.xml
│   │   └── README.md
│   │
│   └── database/
│       └── migrations/
│
├── issuing-ca-system/
│   ├── backend/
│   │   ├── src/
│   │   ├── pom.xml
│   │   └── README.md
│   │
│   ├── database/
│   │   └── migrations/
│   │
│   └── hsm/
│       └── integration-boundaries/
│
├── integration/
│   ├── api-contracts/
│   ├── mtls/
│   └── service-integration/
│
├── monitoring/
│   ├── health/
│   ├── metrics/
│   └── security-monitoring/
│
├── deployment/
│   ├── docker/
│   ├── configuration/
│   └── security/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── acceptance/
│
├── docs/
│   ├── architecture/
│   ├── security/
│   ├── api/
│   ├── operations/
│   └── deployment/
│
├── docker-compose.yml
├── .env.example
└── README.md
```

Frontend applications are intentionally maintained outside this backend repository.

---

# 4. RA System

The Registration Authority provides the identity and certificate request management layer.

## Implemented RA capabilities

* End-entity registration
* Authentication
* Short-lived JWT-based authorization
* Role-Based Access Control (RBAC)
* TOTP MFA for privileged roles
* PKCS#10 CSR verification
* Certificate profile validation
* Certificate request submission
* Request approval and rejection
* CA issuance requests
* CA retry workflow
* Certificate tracking
* Certificate revocation requests
* Revocation retry workflow
* Append-only audit events
* Administrative user management
* Health endpoints
* Database versioning using Flyway

The RA is intentionally prevented from directly performing CA private-key signing operations.

---

# 5. Issuing CA System

The Issuing CA is the cryptographic certificate issuance service.

## Implemented CA capabilities

* PKCS#10 CSR validation
* CSR signature verification
* Certificate profile-based issuance
* CA certificate signing workflow
* PKCS#11 integration boundary
* HSM-backed signing access
* Certificate revocation
* CRL generation
* CA audit records
* Secure service integration boundaries
* Database persistence
* Automated tests

The CA is treated as a higher-trust security component than the RA.

Application users should not receive direct access to CA private keys.

---

# 6. RA-to-CA Integration

The RA and CA communicate through a controlled service-to-service interface.

The intended production trust model is:

RA Service
   │
   │ TLS
   │
   │ Client Certificate
   ▼
CA Service
   │
   │ Authorization
   ▼
Certificate Issuance
   │
   ▼
PKCS#11
   │
   ▼
HSM

The integration must enforce:

1. TLS encryption
2. Mutual TLS authentication
3. Certificate validation
4. Service identity verification
5. Authorization of the RA service
6. Request validation
7. Replay protection where required
8. Secure error handling
9. Audit logging
10. Strict timeout and retry controls

A successful authentication of the RA service does not by itself grant unrestricted CA operations. Each operation must be explicitly authorized.

# 7. HSM and PKCS#11 Security Boundary

The CA private-key boundary is implemented through PKCS#11.

The intended security model is:

CA Application
      │
      │ PKCS#11
      ▼
HSM Provider / PKCS#11 Module
      │
      ▼
Protected CA Private Key
The application requests cryptographic signing from the HSM rather than extracting the CA private key.

The private key should remain non-exportable according to the HSM security policy.

Production deployment requires validation against the target HSM vendor and PKCS#11 implementation.


# 8. Authentication and Authorization

The RA authentication model uses short-lived bearer tokens.

Privileged operations additionally require MFA where configured.

Roles are designed around least privilege and separation of duties.

Example role model:

ADMIN
  │
  ├── User administration
  ├── Security configuration
  └── Administrative operations

OPERATOR
  │
  ├── Certificate workflows
  ├── Request processing
  └── Operational actions

AUDITOR
  │
  ├── Audit records
  └── Read-only security investigation

USER
  │
  ├── Registration
  ├── CSR submission
  └── Certificate status

Authorization must be enforced at the server side. Frontend visibility must never be treated as a security boundary.


# 9. Database Security

The RA and CA use isolated database environments.

Database credentials must:

* Never be committed to Git
* Never be hard-coded in Java source
* Never be exposed through logs
* Use dedicated database accounts
* Follow least-privilege permissions
* Use encrypted database connections in production where supported
* Be rotated according to organizational security policy

Flyway is used for controlled schema migration.




#

# 10. Important Security Boundary

The most important architectural boundary is:

          LOWER TRUST                         HIGHER TRUST

┌──────────────────┐                 ┌─────────────────────┐
│   RA System      │                 │    Issuing CA       │
│                  │                 │                     │
│ Registration     │   mTLS/API      │ Certificate Signing │
│ Authentication   ├────────────────►│ Revocation          │
│ Authorization    │                 │ CRL                 │
│ CSR Workflow     │                 │                     │
└──────────────────┘                 └──────────┬──────────┘
                                                │
                                                │ PKCS#11
                                                ▼
                                      ┌─────────────────────┐
                                      │        HSM          │
                                      │                     │
                                      │ CA Private Key      │
                                      └─────────────────────┘

This separation reduces the impact of a compromise of the RA application and prevents ordinary RA users or application components from directly accessing CA private-key material.

# 11. Project Objective

The objective of KI Issuing Platform is to provide a modular, secure, and enterprise-oriented certificate issuing architecture in which:

* Registration activities are separated from CA cryptographic operations.
* Certificate requests are validated before issuance.
* Approval workflows enforce organizational authorization.
* CA private keys are protected through HSM integration.
* RA and CA communicate through authenticated service boundaries.
* Security-sensitive actions are auditable.
* Database and application security follow least-privilege principles.
* The architecture can be extended toward HA, DR, OCSP, renewal, SIEM, external integrations, and production compliance.

The final acceptance decision must be based on successful verification against the complete system requirements specification (SRS), security requirements, operational requirements, and deployment validation criteria.
