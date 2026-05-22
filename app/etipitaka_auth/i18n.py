from django.conf import settings
from django.utils import translation


class LanguageMiddleware:
    """Selects the active language from the language cookie, defaulting to
    settings.LANGUAGE_CODE. Performs no Accept-Language negotiation: a
    first-time visitor always gets the default language."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        lang = request.COOKIES.get(settings.LANGUAGE_COOKIE_NAME)
        if lang not in dict(settings.LANGUAGES):
            lang = settings.LANGUAGE_CODE
        translation.activate(lang)
        request.LANGUAGE_CODE = lang
        try:
            return self.get_response(request)
        finally:
            translation.deactivate()
