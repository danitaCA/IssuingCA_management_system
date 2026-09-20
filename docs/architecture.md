# Architecture Overview

This project follows a modular monolith architecture for a PKI issuing CA system.

## Modules
- common: reusable domain and shared utilities
- ca-core: issuing CA engine and business logic
- ocsp-service: RFC 6960 compliant responder service

## Layers
- Domain layer for certificates, profiles, and authority concepts
- Application layer for use cases and orchestration
- Infrastructure layer for persistence, HSM, and integrations
- Interfaces layer for REST APIs
