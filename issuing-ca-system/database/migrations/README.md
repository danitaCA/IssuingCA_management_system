# Issuing CA database migrations

The executable Flyway migrations are under `../backend/src/main/resources/db/migration/`, which is the canonical location used by the CA service. Keep this directory for migration planning and operator notes; do not maintain a second divergent copy of migration SQL here.
