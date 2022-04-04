# httpx-auth-awssigv4


[![pypi](https://img.shields.io/pypi/v/httpx-auth-awssigv4.svg)](https://pypi.org/project/httpx-auth-awssigv4/)
[![python](https://img.shields.io/pypi/pyversions/httpx-auth-awssigv4.svg)](https://pypi.org/project/httpx-auth-awssigv4/)
[![Build Status](https://github.com/mmuppidi/httpx-auth-awssigv4/actions/workflows/dev.yml/badge.svg)](https://github.com/mmuppidi/httpx-auth-awssigv4/actions/workflows/dev.yml)
[![codecov](https://codecov.io/gh/mmuppidi/httpx-auth-awssigv4/branch/master/graphs/badge.svg)](https://codecov.io/github/mmuppidi/httpx-auth-awssigv4)



This package provides utilities to add [AWS Signature V4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) authentication infrormation to calls made by python [httpx](https://www.python-httpx.org/) library.


* Documentation: <https://mmuppidi.github.io/httpx-auth-awssigv4>
* GitHub: <https://github.com/mmuppidi/httpx-auth-awssigv4>
* PyPI: <https://pypi.org/project/httpx-auth-awssigv4/>
* MIT License

## Installation

```bash
pip install httpx-auth-awssigv4
```

## Usage

### Basic Usage

This library has primarily been developed to help add authentication support to [httpx](https://www.python-httpx.org/) library while making calls to
REST API deployed using AWS API Gateway service. Will be extended in future to help with calling AWS services.

```python
import httpx
from httpx_auth_awssigv4 import Sigv4Auth

# creating a callable for httpx library
auth = Sigv4Auth(
    access_key="AWS_ACCESS_KEY_ID",
    secret_key="AWS_SECRET_ACCESS_KEY",
    service="execute-api",
    region="us-east-1"
)

# Calling an API endpoint deployed using AWS API Gateway which has
# AWS_IAM set as authorization type

response = httpx.get(
    url="https://<API ID>.execute-api.<Region>.amazonaws.com/prod/detials",
    params={"username": "tstark"},
    auth=auth
)

# Making a post call

response = httpx.get(
    url="https://<API ID>.execute-api.<Region>.amazonaws.com/prod/details",
    params={"username": "tstark"},
    json={"mission": "avengers"},
    auth=auth
)
```

### With STS credentials

`Sigv4Auth` can be used with temporary credentials generated with tools like [aws-sso-util](https://github.com/benkehoe/aws-sso-util).

```python
import boto3
from httpx_auth_awssigv4 import Sigv4Auth

# fetch temporary credentials from AWS STS service
credentials = boto3.Session(profile_name="<profile>").get_credentials()

# creating a callable for httpx library
auth = Sigv4Auth(
    access_key=credentials.access_key,
    secret_key=credentials.secret_key,
    token=credentials.token
    service="execute-api",
    region="us-east-1"
)

```

`Sigv4Auth` can also be used with temporary credentials from AWS STS.

```python
import boto3
from httpx_auth_awssigv4 import Sigv4Auth

# role with `execute-api` permissions
ROLE_ARN="arn:aws:iam::<ACCOUNT ID>:role/<ROLE NAME"

# fetch temporary credentials from AWS STS service
credentials = boto3.client('sts').assume_role(
    RoleArn=ROLE_ARN,
    RoleSessionName="httpxcall"
)["Credentials"]

# creating a callable for httpx library
auth = Sigv4Auth(
    access_key=credentials["AccessKeyId"],
    secret_key=credentials["SecretAccessKey"],
    token=credentials["SessionToken"]
    service="execute-api",
    region="us-east-1"
)

```

## ToDo

- Add examples on usage along with API backend deployment instructions.
- Test the library with AWS services and add integration tests.

## Credits

- This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [waynerv/cookiecutter-pypackage](https://github.com/waynerv/cookiecutter-pypackage) project template.
