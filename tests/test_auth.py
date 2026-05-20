"""Tests for JWT user authentication endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_register_creates_user_and_returns_tokens(test_client: TestClient) -> None:
    resp = test_client.post("/auth/register", json={
        "name": "Alice",
        "email": "alice@example.com",
        "password": "supersecret123",
        "org_name": "Alice's Org",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "alice@example.com"
    assert data["user"]["role"] == "owner"


def test_register_duplicate_email_returns_409(test_client: TestClient) -> None:
    payload = {"name": "Bob", "email": "bob@example.com", "password": "pass123"}
    test_client.post("/auth/register", json=payload)
    resp = test_client.post("/auth/register", json=payload)
    assert resp.status_code == 409


def test_login_returns_tokens(test_client: TestClient) -> None:
    test_client.post("/auth/register", json={
        "name": "Carol",
        "email": "carol@example.com",
        "password": "mypassword",
    })
    resp = test_client.post("/auth/login", json={
        "email": "carol@example.com",
        "password": "mypassword",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "carol@example.com"


def test_login_wrong_password_returns_401(test_client: TestClient) -> None:
    test_client.post("/auth/register", json={
        "name": "Dave",
        "email": "dave@example.com",
        "password": "correct",
    })
    resp = test_client.post("/auth/login", json={
        "email": "dave@example.com",
        "password": "wrong",
    })
    assert resp.status_code == 401


def test_me_returns_user_info(test_client: TestClient) -> None:
    reg = test_client.post("/auth/register", json={
        "name": "Eve",
        "email": "eve@example.com",
        "password": "evespass",
    })
    token = reg.json()["access_token"]
    resp = test_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "eve@example.com"


def test_me_with_invalid_token_returns_401(test_client: TestClient) -> None:
    resp = test_client.get("/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert resp.status_code == 401


def test_refresh_returns_new_access_token(test_client: TestClient) -> None:
    reg = test_client.post("/auth/register", json={
        "name": "Frank",
        "email": "frank@example.com",
        "password": "frankpass",
    })
    refresh_token = reg.json()["refresh_token"]
    resp = test_client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_bearer_token_authenticates_api_endpoint(test_client: TestClient) -> None:
    reg = test_client.post("/auth/register", json={
        "name": "Grace",
        "email": "grace@example.com",
        "password": "gracepass",
    })
    token = reg.json()["access_token"]
    resp = test_client.get("/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
