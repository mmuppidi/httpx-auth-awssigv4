import pytest


@pytest.fixture
def access_key_id():
    return "AccessKeyId"


@pytest.fixture
def secret_access_key():
    return "SecretAccessKey"


@pytest.fixture
def access_token():
    return "AccessToken"


@pytest.fixture
def region():
    return "us-east-1"


@pytest.fixture
def service_name():
    return "execute-api"
