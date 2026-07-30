#!/usr/bin/env python3
"""End-to-end test for Keycloak -> Kong-Role -> Kong ACL -> LOB services."""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", "IAM_Lab_Realm")
KONG_URL = os.getenv("KONG_URL", "http://kong:8000").rstrip("/")
TEST_CLIENT = "kong-role-integration-test"
PUBLIC_ISSUER = f"http://10.0.0.50:9100/realms/{REALM}"
TIMEOUT_SECONDS = 240


def request(
    method: str,
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        return 0, str(exc)


def post_form(url: str, values: dict[str, str]) -> tuple[int, dict[str, Any]]:
    status, body = request(
        "POST",
        url,
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = {"raw": body}
    return status, payload


def wait_until_ready() -> None:
    deadline = time.time() + TIMEOUT_SECONDS
    discovery = f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
    while time.time() < deadline:
        status, _ = request("GET", discovery)
        if status == 200:
            print("[ready] Keycloak realm is available")
            return
        time.sleep(2)
    raise RuntimeError("Keycloak did not become ready")


def admin_token() -> str:
    status, payload = post_form(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
    )
    if status != 200 or "access_token" not in payload:
        raise RuntimeError(f"Unable to obtain Keycloak admin token: {status} {payload}")
    return str(payload["access_token"])


def ensure_test_client(token: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    query = urllib.parse.urlencode({"clientId": TEST_CLIENT})
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients"
    status, body = request("GET", f"{clients_url}?{query}", headers=headers)
    if status != 200:
        raise RuntimeError(f"Unable to inspect Keycloak clients: {status} {body}")

    existing = json.loads(body)
    if existing:
        print(f"[setup] Keycloak client {TEST_CLIENT} already exists")
        return

    client = {
        "clientId": TEST_CLIENT,
        "name": "Kong-Role integration test",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": False,
        "fullScopeAllowed": True,
        "protocolMappers": [
            {
                "name": "realm-roles",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-realm-role-mapper",
                "consentRequired": False,
                "config": {
                    "multivalued": "true",
                    "claim.name": "realm_access.roles",
                    "jsonType.label": "String",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "userinfo.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            }
        ],
    }
    status, body = request(
        "POST",
        clients_url,
        data=json.dumps(client).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json"},
    )
    if status not in (201, 204):
        raise RuntimeError(f"Unable to create Keycloak test client: {status} {body}")
    print(f"[setup] Created Keycloak client {TEST_CLIENT}")


def user_token(username: str) -> str:
    status, payload = post_form(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": TEST_CLIENT,
            "username": username,
            "password": username,
            "scope": "openid",
        },
    )
    if status != 200 or "access_token" not in payload:
        raise RuntimeError(f"Unable to obtain token for {username}: {status} {payload}")
    return str(payload["access_token"])


def decode_payload(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))


def call_lob(path: str, token: str | None = None) -> tuple[int, str]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return request("GET", f"{KONG_URL}{path}", headers=headers)


def wait_for_gateway(token: str) -> None:
    deadline = time.time() + TIMEOUT_SECONDS
    while time.time() < deadline:
        status, _ = call_lob("/lob1", token)
        if status == 200:
            print("[ready] Kong-Role and LOB services are available")
            return
        time.sleep(2)
    raise RuntimeError("Kong-Role gateway did not become ready")


def assert_status(label: str, actual: int, expected: int, body: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected HTTP {expected}, got {actual}: {body}")
    print(f"[pass] {label}: HTTP {actual}")


def main() -> int:
    wait_until_ready()
    ensure_test_client(admin_token())

    expected_roles = {
        "alice": {"lob1-user"},
        "bob": {"lob1-user", "lob2-user"},
        "charlie": {"lob1-user", "lob2-user", "lob3-user"},
    }
    tokens: dict[str, str] = {}
    for username, required_roles in expected_roles.items():
        token = user_token(username)
        claims = decode_payload(token)
        actual_roles = set(claims.get("realm_access", {}).get("roles", []))
        if not required_roles.issubset(actual_roles):
            raise AssertionError(
                f"{username} token roles are incomplete: expected {required_roles}, got {actual_roles}"
            )
        if claims.get("iss") != PUBLIC_ISSUER:
            raise AssertionError(
                f"{username} token issuer mismatch: {claims.get('iss')} != {PUBLIC_ISSUER}"
            )
        tokens[username] = token
        print(f"[pass] {username} token contains {sorted(required_roles)}")

    wait_for_gateway(tokens["alice"])

    status, body = call_lob("/lob1")
    assert_status("missing token is rejected", status, 401, body)

    status, body = call_lob("/lob1", "not-a-jwt")
    assert_status("invalid token is rejected", status, 401, body)

    cases = [
        ("alice", "/lob1", 200, "LOB-1"),
        ("alice", "/lob2", 403, None),
        ("alice", "/lob3", 403, None),
        ("bob", "/lob1", 200, "LOB-1"),
        ("bob", "/lob2", 200, "LOB-2"),
        ("bob", "/lob3", 403, None),
        ("charlie", "/lob1", 200, "LOB-1"),
        ("charlie", "/lob2", 200, "LOB-2"),
        ("charlie", "/lob3", 200, "LOB-3"),
    ]

    for username, path, expected_status, expected_service in cases:
        status, body = call_lob(path, tokens[username])
        assert_status(f"{username} -> {path}", status, expected_status, body)
        if expected_service:
            payload = json.loads(body)
            if payload.get("service") != expected_service:
                raise AssertionError(
                    f"{username} -> {path}: expected {expected_service}, got {payload}"
                )

    print("\nAll Kong-Role integration tests passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - test runner should print complete failure
        print(f"\n[FAIL] {exc}", file=sys.stderr)
        sys.exit(1)
