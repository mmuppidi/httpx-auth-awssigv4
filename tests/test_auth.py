"""Tests for `httpx_auth_awssigv4` package."""

from datetime import datetime
from unittest.mock import patch

import pytest
from httpx import Request

from httpx_auth_awssigv4._auth import SigV4Auth


@pytest.fixture
def auth(access_key_id, secret_access_key, access_token, region, service_name):
    return SigV4Auth(
        access_key=access_key_id, secret_key=secret_access_key, token=access_token, service=service_name, region=region
    )


def test_get_signature_key(auth):
    key = auth.get_signature_key(date_stamp="20220403")

    assert key == b"\xcc\xaf\xbd\xc9w\xbe\x91Ibfd\xb1\xa2v\xb0\xb1v\xd7\xe8*\x05\xc8\x04\x91DZ\x7f\xb9\x0e\xa4\xf9\xc7"


def test_get_canonical_request(auth):
    pass


def test_get_authorization_header(auth, access_key_id):
    header = auth.get_authorization_header(credential_scope="scope", signature="signature")

    assert header == (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/scope, SignedHeaders=host;x-amz-date, Signature=signature"
    )


@patch("httpx_auth_awssigv4._auth.datetime")
def test_callable_permanent_creds(mock_dt, auth, access_key_id, access_token):
    mock_dt.utcnow.return_value = datetime(year=2020, month=4, day=20, hour=20, minute=30, second=30)

    request = Request(
        method="GET", url="https://www.example.com/details", params={"username": "tstark", "team": "avengers"}
    )

    signed_request = auth(request=request)

    assert signed_request.headers["authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/20200420/"
        f"{auth._region}/{auth._service}/aws4_request, SignedHeaders=host;x-amz-date, "
        "Signature=8f841949ffd9e2f2ca5406f52cf5aa5e06b1d2ed8140b444d0ac46a845f627ec"
    )

    assert signed_request.headers["x-amz-security-token"] == access_token
    assert signed_request.headers["x-amz-date"] == "20200420T203030Z"


@patch("httpx_auth_awssigv4._auth.datetime")
def test_callable_sts_creds(mock_dt, auth, access_key_id):
    mock_dt.utcnow.return_value = datetime(year=2020, month=4, day=20, hour=20, minute=30, second=30)

    request = Request(
        method="GET", url="https://www.example.com/details", params={"username": "tstark", "team": "avengers"}
    )

    auth._token = None

    signed_request = auth(request=request)

    print(signed_request.headers["authorization"])

    assert signed_request.headers["authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/20200420/"
        f"{auth._region}/{auth._service}/aws4_request, SignedHeaders=host;x-amz-date, "
        "Signature=8f841949ffd9e2f2ca5406f52cf5aa5e06b1d2ed8140b444d0ac46a845f627ec"
    )

    assert "x-amz-security-token" not in signed_request.headers
    assert signed_request.headers["x-amz-date"] == "20200420T203030Z"


@patch("httpx_auth_awssigv4._auth.datetime")
def test_callable_sts_creds_post_call(mock_dt, auth, access_key_id):
    mock_dt.utcnow.return_value = datetime(year=2020, month=4, day=20, hour=20, minute=30, second=30)

    request = Request(
        method="GET",
        url="https://www.example.com/details",
        params={"username": "tstark", "team": "avengers"},
        json={"upgarde": "suit"},
    )

    auth._token = None

    signed_request = auth(request=request)

    assert signed_request.headers["authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/20200420/"
        f"{auth._region}/{auth._service}/aws4_request, SignedHeaders=host;x-amz-date, "
        "Signature=637069169cdbb543db43d56c43b10e43e4d256187dcbcef5a30d905eca8a8182"
    )

    assert "x-amz-security-token" not in signed_request.headers
    assert signed_request.headers["x-amz-date"] == "20200420T203030Z"
