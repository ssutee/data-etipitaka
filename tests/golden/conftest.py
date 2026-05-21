import os
import pytest
import requests


def pytest_collection_modifyitems(items):
    # Golden snapshot cases assume the pristine seed dataset. Behavioral tests
    # mutate the shared database (registration creates a user, which would
    # pollute sharing_list). Force the golden module to run first so it sees
    # the clean seed; behavioral runs afterward where its writes harm nothing.
    items.sort(key=lambda item: 0 if "test_golden" in item.nodeid else 1)


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
