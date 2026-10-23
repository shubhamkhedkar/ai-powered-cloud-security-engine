import os

import pytest

for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
             "AWS_DEFAULT_REGION": "ap-south-1"}.items():
    os.environ[k] = v
os.environ.pop("AWS_PROFILE", None)
os.environ.pop("AI_API_KEY", None)


@pytest.fixture
def aws():
    from moto import mock_aws

    with mock_aws():
        import boto3
        yield boto3.Session(region_name="ap-south-1")
