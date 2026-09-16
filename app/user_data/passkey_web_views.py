"""Browser-session passkey endpoints.

Plain Django views, not DRF: api_view exempts CSRF unless SessionAuthentication
authenticates the request, and these endpoints are anonymous. Keeping Django's
CSRF middleware in force stops login CSRF (an attacker signing a victim's
browser into the attacker's account).

Being a plain Django view also means none of DRF's machinery applies here --
in particular PasskeyRateThrottle (user_data/passkey_views.py) never runs for
this path, unlike every other passkey endpoint. nginx's own rate limiting is
the only throttle in front of this view; see Task 23 for the
`/login/passkey/`-specific zone.
"""
import json
import logging

from django.contrib.auth import login
from django.http import JsonResponse, RawPostDataException, UnreadablePostError
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from . import passkey_service as service
from .views import _safe_redirect_target

log = logging.getLogger(__name__)

# Matches django.contrib.auth's own default AUTHENTICATION_BACKENDS (this
# project sets none of its own in settings.py), pinned explicitly here so a
# future change to that setting can't silently change which backend a
# passkey login records on the session without this file's tests noticing.
SESSION_BACKEND = 'django.contrib.auth.backends.ModelBackend'


def json_body(request):
    """The request's JSON object, or {} for anything else.

    Catches RecursionError alongside ValueError/UnicodeDecodeError: a
    pathologically deep JSON body (json.loads has no nesting-depth limit of
    its own) exhausts Python's recursion budget the same way it does for the
    DRF endpoints (see user_data/drf_handlers.py) -- but this is a plain
    Django view, never dispatched through DRF's APIView, so DRF's global
    EXCEPTION_HANDLER never runs for it. Without this, that RecursionError
    would propagate out of this view as an unhandled 500 instead of the
    clean 400 every other malformed body already gets here.

    Also catches RawPostDataException/UnreadablePostError: @csrf_protect's
    _check_token() reads request.POST first, looking for a
    csrfmiddlewaretoken form field, on *every* POST -- even one whose real
    token arrives via the X-CSRFToken header. Reading request.POST on a
    multipart body consumes the input stream, so request.body here would
    otherwise raise RawPostDataException (not a SuspiciousOperation, so
    Django's own exception handling would not turn it into a clean 400 the
    way it does for RequestDataTooBig) -- reachable by any anonymous caller
    on this unthrottled endpoint.
    """
    try:
        data = json.loads(request.body or b'{}')
    except RecursionError:
        # Matches drf_handlers.exception_handler's own reasoning: a
        # pathologically deep body and a genuine runaway recursion in this
        # project's own code would otherwise be indistinguishable once both
        # collapse to the same clean 400 below -- log which one this was.
        # Guarded because logging itself must never turn this already-
        # exceptional path into a second, unhandled exception.
        try:
            log.warning('recursion limit hit while parsing the body of %s', request.path)
        except Exception:
            pass
        return {}
    except (ValueError, UnicodeDecodeError, RawPostDataException, UnreadablePostError):
        return {}
    return data if isinstance(data, dict) else {}


@require_POST
@csrf_protect
def login_passkey(request):
    data = json_body(request)
    try:
        user = service.finish_login(data.get('challenge_id'), data.get('credential'))
    except service.InactiveUser:
        return JsonResponse({'detail': _('This account is not active. Please verify your email.')},
                            status=400)
    except service.InvalidCredentials:
        return JsonResponse({'detail': _('Unable to log in with provided credentials.')},
                            status=400)
    login(request, user, backend=SESSION_BACKEND)
    next_url = data.get('next') if isinstance(data.get('next'), str) else ''
    response = JsonResponse({'redirect': _safe_redirect_target(request, next_url)})
    # This response sets a session cookie -- it must never be cached and
    # replayed back to a later, different visitor of a shared cache/browser.
    response['Cache-Control'] = 'no-store'
    return response
