import os
import pytest
import requests


def pytest_addoption(parser):
    parser.addoption(
        "--record", action="store_true", default=False,
        help="Record golden snapshots instead of asserting against them",
    )
    parser.addoption(
        "--base-url", action="store",
        default=os.environ.get("GOLDEN_BASE_URL", "http://localhost:1338"),
        help="Base URL of the running app under test",
    )


@pytest.fixture(scope="session")
def record(pytestconfig):
    return pytestconfig.getoption("--record")


@pytest.fixture(scope="session")
def base_url(pytestconfig):
    return pytestconfig.getoption("--base-url").rstrip("/")


@pytest.fixture(scope="session")
def http():
    session = requests.Session()
    yield session
    session.close()
