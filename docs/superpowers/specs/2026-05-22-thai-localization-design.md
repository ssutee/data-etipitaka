# Thai Localization — Design

**Date:** 2026-05-22
**Status:** Approved

## Goal

Localize the E-Tipitaka account web UI to Thai and make Thai the default
language. The site stays bilingual: English remains available, but every
first-time visitor sees Thai regardless of browser language. English appears
only when a user explicitly switches.

## Scope

All user-facing English text is localized:

- HTML page templates and form/table fragments
- The verification email (subject + body)
- DRF API validation error messages (`serializers.py`)
- AngularJS client-side strings (`app.js`)

Out of scope: Django built-ins (admin, password validators, DRF default error
strings, the password-reset *emails*) already ship Thai translations and need
no work.

## Language resolution

Django gettext provides the translation machinery. Language selection uses a
custom thin middleware instead of Django's `LocaleMiddleware` — the requirement
is "no browser-language negotiation," which `LocaleMiddleware` cannot express
(it always honors `Accept-Language` before falling back to `LANGUAGE_CODE`).

URL-prefix i18n (`i18n_patterns`, e.g. `/th/login/`) was rejected: it would
break the fixed API paths the iOS/Android/AngularJS clients depend on
(`/login/`, `/upload/`, `/user_data_list/`, etc.).

### `app/etipitaka_auth/i18n.py` — `LanguageMiddleware`

```python
from django.conf import settings
from django.utils import translation

class LanguageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        lang = request.COOKIES.get(settings.LANGUAGE_COOKIE_NAME)
        if lang not in dict(settings.LANGUAGES):
            lang = settings.LANGUAGE_CODE
        translation.activate(lang)
        request.LANGUAGE_CODE = lang
        response = self.get_response(request)
        translation.deactivate()
        return response
```

Behavior:

- No language cookie, or an invalid value → `LANGUAGE_CODE` (Thai).
- Valid cookie → that language. The cookie is written only by the switcher.
- No `Accept-Language` negotiation anywhere.

### `settings.py` changes

- `LANGUAGE_CODE = 'th'`
- `LANGUAGES = [('th', 'ไทย'), ('en', 'English')]`
- `LOCALE_PATHS = [os.path.join(BASE_DIR, 'locale')]`
- Add `'etipitaka_auth.i18n.LanguageMiddleware'` to `MIDDLEWARE`, immediately
  after `SessionMiddleware`. Django's `LocaleMiddleware` is NOT added.

## Language switcher

- `urls.py`: add `path('i18n/setlang/', django.views.i18n.set_language)`. The
  built-in view writes the `LANGUAGE_COOKIE_NAME` cookie and redirects to
  `next`.
- `base.html` navbar: a small `<form method="post" action="/i18n/setlang/">`
  with a `ไทย / EN` toggle and a hidden `next` field set to the current path.
- `<html lang="...">` is driven by `{% get_current_language %}` instead of the
  hardcoded `lang="en"`.

## String extraction

| Surface | Files | Method |
|---|---|---|
| Page templates | `index.html`, `login.html`, `signup.html`, `validate.html`, `user_data.html`, `registration/password_reset_*.html` (4) | `{% load i18n %}` + `{% trans %}` / `{% blocktrans %}` |
| Layout / navbar | `base.html` (Home, Login, Register, Logout, Upload, title) | `{% trans %}` |
| Fragments | `forms/login_form.html`, `forms/signup_form.html`, `fragments/table_header.html`, `fragments/table_body.html` | `{% load i18n %}` + `{% trans %}` |
| API errors | `user_data/serializers.py` (4 validation strings) | `gettext` |
| Email + responses | `user_data/auth_views.py` (subject string, `detail` responses) | `gettext` |
| Email body | `templates/email/verify_email.txt` | `{% load i18n %}` + `{% trans %}` / `{% blocktrans %}` |
| Upload form | `user_data/forms.py` (`UploadFileForm` label, help_text) | `gettext_lazy` |
| JS strings | `assets/app.js` ("Are you sure?", "password is too short", "passwords not match", "Loading...") | `window.i18n` dict |

### JS strings

`base.html` injects a `window.i18n` JavaScript object whose values come from
`{% trans %}` tags. `app.js` reads `window.i18n.<key>` instead of the hardcoded
literals. This keeps every string — including the JS ones — inside the single
`django.po` catalog; no separate `djangojs` catalog or `JavaScriptCatalog`
endpoint is needed for four strings.

The verification email is rendered during the registration request, so it
picks up whatever language is active for that request (the user's current
cookie choice).

## Catalog workflow

- Catalog file: `app/locale/th/LC_MESSAGES/django.po`.
- Generated with `makemessages -l th` on the developer machine, Thai
  translations filled in, reviewed by the project owner.
- Compiled `.po` → `.mo` with `compilemessages` on the developer machine.
- **The compiled `.mo` is committed to the repo.** `makemessages` /
  `compilemessages` require the GNU `gettext` binaries, which the slim web
  Docker image deliberately does not have (apt was removed in a prior session).
  At runtime Django reads the `.mo` directly with no gettext binary, so
  committing the `.mo` keeps the image unchanged.

## Testing

### Unit tests

- Add `LanguageMiddleware` tests: cookie absent → Thai; cookie `en` → English;
  invalid cookie value → Thai.
- Add a switcher test: POST to `/i18n/setlang/` sets the cookie and redirects.
- Coverage stays at or above the 90% gate.

### Golden harness

The golden harness proves the new Django 5.2 stack matches the old Python 2 /
Django 1.9 stack, which serves English only. Localizing HTML pages and the
Thai serializer error strings breaks that cross-stack equivalence **by design**.

- Golden snapshots for localized HTML pages and localized API error strings are
  re-recorded against the new stack. For those endpoints the test converts from
  a cross-stack equivalence proof to a same-stack snapshot — it still guards
  response structure and status, no longer body-text parity with the old stack.
- API responses whose body is not localized (JSON shape, tokens, status codes)
  remain valid cross-stack checks.
- `tests/golden/README.md` is updated to document which snapshots are now
  same-stack and why.

## Files touched

- New: `app/etipitaka_auth/i18n.py`, `app/locale/th/LC_MESSAGES/django.po`,
  `app/locale/th/LC_MESSAGES/django.mo`
- Modified: `settings.py`, `urls.py`, `base.html`, all page templates,
  form/table fragments, `verify_email.txt`, `serializers.py`, `auth_views.py`,
  `forms.py`, `assets/app.js`, `tests/golden/README.md`, golden snapshots
- New tests for the middleware and switcher
