# Registration Authority backend

This Spring Boot service contains the RA implementation: identity/user management, RBAC and TOTP MFA, PKCS#10 CSR verification, request profiles, approval/rejection workflow, audit events, and mTLS integration with the separate Issuing CA service.

Run from this directory with Java 21 and Maven 3.9+: `mvn test` then `mvn spring-boot:run`. Configure `DB_*`, `JWT_SECRET` (at least 32 bytes), and bootstrap administrator values in the environment. The root `docker-compose.yml` starts the local MariaDB service. Full API and security notes are in the repository root README and this service's `application.yml`.
