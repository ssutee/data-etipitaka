"""Global DRF exception handler.

Wired in via REST_FRAMEWORK['EXCEPTION_HANDLER'], so this runs for every DRF
view in the project, not just the passkey endpoints.

json.loads() recurses once per level of nesting with no size limit of its
own. A pathologically deep JSON body (nested single-key objects or arrays,
~40KB is enough) exhausts Python's recursion budget and raises
RecursionError from inside DRF's JSONParser -- which only catches
ValueError -- while parsing request.data. RecursionError is not a
rest_framework.exceptions.APIException, so DRF's own default handler
(rest_framework.views.exception_handler) returns None for it, and the view
lets it propagate as an unhandled 500. This handler intercepts it first and
turns it into a clean 400.

By the time Python raises RecursionError the interpreter has already
unwound the stack back down to wherever the enclosing try/except lives
(here, DRF's APIView.dispatch()) -- exception propagation pops frames as it
goes, it does not preserve them -- so this handler is not itself running
anywhere near an exhausted recursion budget. It still does the least
possible work on this path anyway: no inspecting `exc`, no formatting a
message from request data, straight to a fixed, translatable string.

The isinstance check is deliberately narrow (RecursionError only, not the
wider RuntimeError it subclasses): only a hostile/malformed body should
ever turn into a 400 here, and a genuine runaway recursion bug elsewhere in
this project's own code is exactly the kind of thing that must still 500
loudly, not get silently swallowed alongside it.
"""
import logging

from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as _default_exception_handler
from rest_framework.views import set_rollback

log = logging.getLogger(__name__)


def exception_handler(exc, context):
    if isinstance(exc, RecursionError):
        # A genuine runaway recursion in our own code would otherwise be
        # indistinguishable from hostile input once it is mapped to the same
        # clean 400 -- log it as a warning so an operator can tell the two
        # apart. Guarded because logging must not itself risk turning this
        # already-exceptional path into a second, unhandled exception.
        try:
            request = (context or {}).get('request')
            log.warning('recursion limit hit while handling %s',
                       getattr(request, 'path', '<unknown path>'))
        except Exception:
            pass
        set_rollback()
        return Response({'detail': _('Malformed request.')}, status=status.HTTP_400_BAD_REQUEST)
    return _default_exception_handler(exc, context)
