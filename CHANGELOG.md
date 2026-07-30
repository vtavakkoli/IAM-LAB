# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog.

## [Unreleased]

### Added

- End-to-end integration test covering real Keycloak tokens, Kong-Role JWT validation, Kong ACL decisions, and all three LOB services.
- GitHub Actions workflow that builds the complete Docker Compose lab and runs the integration matrix.
- Dedicated `gateway/kong.yml` using Kong-Role 2.0.0 authenticated role groups.
- Publication-readiness documentation set:
  - professional README refresh
  - disclaimer document
  - contributing guide
  - roadmap
  - security policy
  - code of conduct
  - pull request and issue templates
  - root-level `.gitignore`
  - MIT license file

### Changed

- Kong is now built directly from a pinned commit of `vtavakkoli/Kong-Role` instead of a local plugin copy.
- Authorization now uses all `realm_access.roles` values as Kong authenticated groups; synthetic role consumers are no longer required.
- Enabled Keycloak dynamic backchannel URLs so Kong can retrieve discovery and JWKS data over the internal Compose network.
- Repository structure and metadata documentation for clearer onboarding.
- Replaced license placeholder with full MIT license text.

### Removed

- Local Kong Dockerfile and duplicated `kong/oidc` plugin implementation.
- Legacy Kong v1 declarative configuration and role-consumer records.
- Duplicate per-project `.gitignore` files consolidated into root-level ignore rules.
