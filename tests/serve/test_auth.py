import pytest
from fastapi import HTTPException, Request

from threat_thinker.serve.auth import APIKeyAuthenticator
from threat_thinker.serve.config import AuthConfig


def _request_with_header(name: str, value: str) -> Request:
    scope = {
        "type": "http",
        "headers": [(name.lower().encode(), value.encode())],
    }
    return Request(scope)


def test_auth_bearer_token_success():
    authenticator = APIKeyAuthenticator(
        AuthConfig(
            mode="api_key",
            scheme="bearer",
            header_name="Authorization",
            api_keys=["secret"],
        )
    )
    request = _request_with_header("Authorization", "Bearer secret")
    assert authenticator.authenticate(request) == "secret"


def test_auth_rejects_missing_token():
    authenticator = APIKeyAuthenticator(
        AuthConfig(
            mode="api_key",
            scheme="bearer",
            header_name="Authorization",
            api_keys=["secret"],
        )
    )
    request = _request_with_header("Authorization", "")
    with pytest.raises(HTTPException):
        authenticator.authenticate(request)
