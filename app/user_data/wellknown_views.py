"""Association files that let the native apps use passkeys for this domain.

Only `webcredentials` is declared for iOS (no universal-link paths), so links
in emails always open in the browser.

Both files are fetched directly by the OS (Apple's CDN, Android's Digital
Asset Links verifier), never by a logged-in browser, so these views must
work with no authentication and no CSRF token, and must answer GET/HEAD
only -- everything else (POST/PUT/DELETE/...) gets 405. `csrf_exempt` is
required here: without it CsrfViewMiddleware would 403 a cookie-less POST
before the method check below ever ran, which would leak a CSRF Forbidden
page instead of a clean 405.
"""
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

_NOT_FOUND = {'detail': 'Not found.'}


@require_http_methods(['GET', 'HEAD'])
@csrf_exempt
def apple_app_site_association(request):
    if not settings.PASSKEY_IOS_APP_IDS:
        # An empty {'webcredentials': {'apps': []}} would actively tell iOS
        # that no app is associated with this domain -- worse than a plain
        # 404. Use JSON rather than Django's HTML 404, which varies with
        # DEBUG, to match the assetlinks behaviour below.
        return JsonResponse(_NOT_FOUND, status=404)
    return JsonResponse({'webcredentials': {'apps': list(settings.PASSKEY_IOS_APP_IDS)}})


@require_http_methods(['GET', 'HEAD'])
@csrf_exempt
def assetlinks(request):
    if not settings.PASSKEY_ANDROID_PACKAGE or not settings.PASSKEY_ANDROID_CERT_SHA256:
        # JSON rather than Django's HTML 404, which varies with DEBUG.
        return JsonResponse(_NOT_FOUND, status=404)
    return JsonResponse([{
        'relation': ['delegate_permission/common.get_login_creds'],
        'target': {'namespace': 'android_app',
                   'package_name': settings.PASSKEY_ANDROID_PACKAGE,
                   'sha256_cert_fingerprints': list(settings.PASSKEY_ANDROID_CERT_SHA256)},
    }], safe=False)
