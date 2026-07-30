# IAM Lab: Kong-Role, Keycloak, LDAP & .NET Demo

> **Written by Vahid Tavakkoli, 2026**

A hands-on Identity and Access Management lab demonstrating:

- **Keycloak** for identity, OpenID Connect, and realm-role assignments
- **Kong Community Gateway** with the external [Kong-Role](https://github.com/vtavakkoli/Kong-Role) plugin
- **Kong ACL** for route-level authorization using authenticated JWT role groups
- **OpenLDAP** as a user-directory source
- **.NET 8** web applications and protected LOB APIs

## Demo disclaimer

This repository is a local lab. Credentials, HTTP endpoints, and hostnames are intentionally developer-friendly and are not production-safe. See [DISCLAIMER.md](DISCLAIMER.md).

## Architecture

```text
OpenLDAP ──► Keycloak ──JWT──► Kong-Role ──authenticated groups──► Kong ACL
                                      │                              │
                                      └──────────────────────────────┘
                                                     │
                                             LOB1 / LOB2 / LOB3
```

The local copy of the Kong plugin has been removed. Docker Compose builds the gateway directly from a pinned commit of the separate `Kong-Role` repository:

```text
Kong-Role commit: f1fdd2e6e9c4b8b58fd0b3b76e67589d18c1abff
Plugin version:   2.0.0
```

This commit includes a reproducible container dependency fix that vendors pinned `lua-resty-openidc`, `lua-resty-jwt`, and `lua-resty-hmac` runtime modules without relying on mutable LuaRocks mirrors. The pin keeps the lab reproducible while the gateway implementation remains maintained in one repository.

## Repository structure

```text
.
├── docker-compose.yml
├── gateway/
│   └── kong.yml
├── keycloak/
│   └── config/IAM_Lab_Realm.json
├── ldap/
│   └── bootstrap.ldif
├── lob-services/
├── WebApp1/
├── WebApp2/
├── tests/integration/
│   └── test_kong_role.py
└── .github/workflows/
    └── kong-role-integration.yml
```

## Start the lab

```bash
docker compose up --build
```

Primary endpoints:

- Keycloak: `http://localhost:9100`
- phpLDAPadmin: `http://localhost:9150`
- Kong proxy: `http://localhost:9180`
- Kong Admin API: `http://localhost:9181`
- WebApp1: `http://localhost:9101`
- WebApp2: `http://localhost:9102`

The sample configuration uses `10.0.0.50` as the browser-facing host. Change `KC_HOSTNAME`, the web-app public URLs, and redirect URIs in `docker-compose.yml` when your development host uses another address.

## Kong-Role v2 behavior

The gateway uses one global `oidc-role` plugin instance to:

1. validate bearer JWT signatures through Keycloak discovery/JWKS;
2. verify the expected issuer and the configured `preferred_username` principal;
3. extract all values from `realm_access.roles`;
4. publish the roles as Kong authenticated groups;
5. let each route ACL return `200` or `403` based on the required LOB role.

No synthetic Kong consumers are required.

Role matrix:

| User | LOB1 | LOB2 | LOB3 |
|---|---:|---:|---:|
| alice | allowed | denied | denied |
| bob | allowed | allowed | denied |
| charlie | allowed | allowed | allowed |

## Run the integration test

The test creates a temporary direct-grant Keycloak client through the Admin API, requests real JWTs for Alice, Bob, and Charlie, and calls every protected route through Kong.

```bash
docker compose --profile integration-test up \
  --build \
  --abort-on-container-exit \
  --exit-code-from integration-test \
  integration-test
```

It verifies:

- missing token returns `401`;
- malformed token returns `401`;
- Keycloak tokens contain the expected issuer, principal, and realm roles;
- allowed role/route combinations return `200` and reach the correct LOB service;
- denied role/route combinations return `403`;
- users with multiple roles retain all authorization groups.

Clean up afterward:

```bash
docker compose --profile integration-test down --volumes --remove-orphans
```

The same test runs in GitHub Actions through `.github/workflows/kong-role-integration.yml`.

## Demo credentials

- Keycloak admin: `admin` / `admin`
- LDAP admin DN: `cn=admin,dc=iam,dc=lab`
- LDAP password: `admin`
- Users: `alice/alice`, `bob/bob`, and `charlie/charlie`

## Governance

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CHANGELOG.md](CHANGELOG.md)
- [ROADMAP.md](ROADMAP.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [LICENSE](LICENSE)
- [DISCLAIMER.md](DISCLAIMER.md)
