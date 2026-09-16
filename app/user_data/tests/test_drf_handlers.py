"""A pathologically deep JSON body must never 500 -- on any DRF endpoint.

json.loads() recurses once per nesting level with no size limit of its own;
a ~40KB body of nested single-key objects/arrays exhausts Python's
recursion budget and raises RecursionError, which DRF's JSONParser does not
catch (it only catches ValueError) and which is not an APIException, so the
default DRF exception handler lets it propagate as an unhandled 500. This
must resolve to 400 everywhere DRF parses a JSON body, not just the passkey
endpoints -- so the fix lives in a global EXCEPTION_HANDLER, not per-view.
"""
import pytest
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


def _nested_body(depth):
    return '{"a":' * depth + '1' + '}' * depth


_URLS = [
    '/api/passkeys/login/begin/',
    '/api/passkeys/login/finish/',
    '/api/passkeys/signup/begin/',
    '/api/passkeys/signup/finish/',
    '/rest-auth/login/',
]


@pytest.mark.parametrize('url', _URLS)
def test_deeply_nested_json_body_is_400_not_500(url):
    # The exact nesting depth that overflows Python's recursion budget
    # depends on how many stack frames the caller already used before
    # json.loads() runs -- through nginx/gunicorn's full WSGI + middleware
    # stack this was observed at depth ~9935, but that same depth parses
    # cleanly in-process here (this test client's call chain into
    # request.data is shallower), so asserting on it would be flaky per
    # endpoint. 20000 is comfortably past the threshold in every context
    # this suite runs in.
    client = APIClient()
    resp = client.post(url, _nested_body(20000), content_type='application/json')
    assert resp.status_code == 400
