import pytest

from endpoints import GOLDEN_CASES
from normalize import normalize_response
from snapshot import save_snapshot, load_snapshot


@pytest.mark.parametrize("case", GOLDEN_CASES, ids=[c.id for c in GOLDEN_CASES])
def test_golden(case, http, base_url, record):
    response = case.execute(http, base_url)
    actual = normalize_response(response)
    if record:
        save_snapshot(case.id, actual)
        pytest.skip("recorded snapshot for " + case.id)
    expected = load_snapshot(case.id)
    assert actual == expected, "behavior drift on endpoint case: " + case.id
