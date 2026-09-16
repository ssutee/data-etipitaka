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

from django.contrib.auth import login
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from . import passkey_service as service
from .views import _safe_redirect_target

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
    """
    try:
        data = json.loads(request.body or b'{}')
    except (ValueError, UnicodeDecodeError, RecursionError):
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
    return JsonResponse({'redirect': _safe_redirect_target(request, next_url)})
