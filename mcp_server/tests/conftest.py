import pytest


@pytest.fixture
def anyio_backend():
    # The mcp SDK brings anyio (and its pytest plugin); run async tests on
    # asyncio only so trio need not be installed.
    return 'asyncio'
