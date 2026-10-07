# PKI Issuing Platform

Backend-only monorepo for the Registration Authority (RA) and Issuing Certificate Authority (CA), following the supplied project overview. Frontend directories/code are intentionally not included.

## Structure

- `ra-system/backend/` — implemented RA REST API (Java 21, Spring Boot, MariaDB, Flyway)
- `ra-system/database/migrations/` — migration notes; executable Flyway SQL is in the RA backend classpath under `src/main/resources/db/migration/`
- `issuing-ca-system/backend/` — Spring Boot CA backend with PKCS#10 validation, profile-based issuance, PKCS#11 HSM signer access, revocation, audit records, and on-demand CRL generation
- `issuing-ca-system/database/migrations/` and `issuing-ca-system/hsm/` — CA migration notes and PKCS#11 integration boundaries
- `integration/`, `monitoring/`, `deployment/`, `tests/`, and `docs/` — backend API contracts, operations, tests, and documentation boundaries

## Local development

1. Copy `.env.example` to `.env`, replace all example passwords/secrets, and keep `.env` untracked. Never commit real secrets.
2. Start two isolated local databases from the repository root with `docker compose up -d`.
3. Run RA tests and start the RA service from `ra-system/backend/` with `mvn test` then `mvn spring-boot:run`.
4. CA issuance needs a configured PKCS#11 HSM identity and inbound mTLS. From `issuing-ca-system/backend/`, run `mvn test`. Do not enable keyless mTLS bypass or run the CA as production-ready without hardware/integration validation.

The RA currently supports end-entity registration, RBAC, TOTP MFA for privileged roles, PKCS#10 CSR verification, profile checks, approval/rejection workflow, mTLS CA issue/revocation calls, certificate tracking, and append-only audit events. The CA now implements initial HSM-backed issuance, revocation, and CRL generation. OCSP, dynamic CA/profile management, renewal, key lifecycle operations, HA/DR, external integrations, and production compliance validation remain before full SRS acceptance.

## RA API summary

Routes use `/api/v1`. Authentication returns a short-lived bearer JWT. End entities register via `/auth/register`; privileged users must complete TOTP enrollment. Available APIs include auth/MFA, admin user management, profiles, CSR request submission/listing, approval/rejection, CA retry, certificate revocation/retry, audit logs, and health checks. See `ra-system/backend/README.md` for API details and mTLS contract.

Apply the complete CA and RA acceptance criteria from the source SRS documents before production use. TLS ingress, database encryption/HA, SIEM forwarding, backup/DR, HSM vendor integration, and 80% coverage remain deployment or follow-up work.
