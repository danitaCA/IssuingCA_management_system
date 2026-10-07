# Issuing CA backend

Spring Boot 3 / Java 21 CA service implementing an initial SRS milestone: PKCS#10 verification, profile-based certificate issuance, idempotent issue requests, HSM-backed signing through JDK PKCS#11, certificate persistence, revocation, append-only audit events, and on-demand signed CRL generation.

## Local and production configuration

Run `mvn test` here. The root Compose file starts the CA MariaDB database; set `CA_DB_*` and a non-empty secret-managed password. Flyway applies `src/main/resources/db/migration/`.

The service deliberately has **no software-key fallback**. Set `HSM_PKCS11_CONFIG` to the vendor/JDK PKCS#11 provider configuration, `HSM_CA_KEY_ALIAS` to a token alias containing the CA certificate and non-exportable private key, and `HSM_PIN` from a secret manager. The configured certificate must be valid and have CA basic constraints plus `keyCertSign` and `cRLSign` key usages. Signing invokes the token provider; private key bytes are never loaded or persisted by this service.

For production set `CA_TLS_ENABLED=true`, provide the server PKCS#12 key store and client trust store, and configure `CA_ALLOWED_CLIENT_SUBJECTS` as semicolon-separated exact subject DNs. The RA issue/revoke/profile APIs require a trusted, allow-listed client certificate. `CA_MTLS_REQUIRED=false` is accepted only when the Spring `local` profile is active. Do not use that bypass in deployments. The public CRL endpoint is `GET /api/v1/crl`.

## Implemented API

- `POST /api/v1/certificates/issue` — verify and sign a PKCS#10 request using `tls-server`, `client-auth`, or `code-signing` profile.
- `POST /api/v1/certificates/revoke` — record an allowed revocation reason against the matching request ID and serial.
- `GET /api/v1/profiles` — list supported fixed profiles.
- `GET /api/v1/crl` — return a newly generated DER-encoded CRL.

Issue requests use the RA contract and request ID as an idempotency key. Reusing an ID for a different CSR/profile is rejected. RSA 2048/3072/4096 and ECDSA P-256/P-384/P-521 keys are accepted; CSR signatures must use SHA-256/384/512. Profiles and default validity are code/config-defined, not dynamically managed.

## Remaining SRS work

This is an initial implementation, **not SRS complete or production-certified**. Dynamic CA configuration/profile management, renewal scheduling/notifications, an OCSP responder, CRL scheduling/publication hosting, key generation/rotation/backup/recovery/destruction workflows, vendor HSM validation, external LDAP/email/Fayda/SIEM integrations, HA/DR, performance targets, backup procedures, standards evidence, and broader integration/acceptance coverage remain outstanding. Hardware HSM and real MariaDB integration were not available for the unit tests.
