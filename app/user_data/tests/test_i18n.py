from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory
from django.utils import translation

from etipitaka_auth.i18n import LanguageMiddleware


def _activated_language(cookie_value=None):
    """Run LanguageMiddleware over a fake request, return the language
    that was active while the view ran."""
    request = RequestFactory().get('/')
    if cookie_value is not None:
        request.COOKIES[settings.LANGUAGE_COOKIE_NAME] = cookie_value
    captured = {}

    def get_response(req):
        captured['active'] = translation.get_language()
        captured['request_attr'] = req.LANGUAGE_CODE
        return HttpResponse('ok')

    LanguageMiddleware(get_response)(request)
    return captured


def test_no_cookie_defaults_to_thai():
    captured = _activated_language()
    assert captured['active'] == 'th'
    assert captured['request_attr'] == 'th'


def test_valid_english_cookie_selects_english():
    captured = _activated_language('en')
    assert captured['active'] == 'en'
    assert captured['request_attr'] == 'en'


def test_invalid_cookie_falls_back_to_thai():
    captured = _activated_language('xx')
    assert captured['active'] == 'th'
