# Thai Localization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Localize the E-Tipitaka account web UI to Thai, with Thai as the default language for every first-time visitor and English available via a switcher.

**Architecture:** Django gettext provides translation. A custom thin `LanguageMiddleware` replaces Django's `LocaleMiddleware` — it reads the language cookie and defaults to Thai with no browser-language negotiation. All user-facing strings are wrapped in `{% trans %}` / `gettext()`; a single `locale/th/LC_MESSAGES/django.po` catalog holds the Thai translations, compiled to a `.mo` that is committed to the repo (the slim web image has no gettext binary).

**Tech Stack:** Django 5.2, Django REST Framework, gettext, AngularJS (templates), Docker Compose.

---

## Conventions

- All shell commands run from the repo root unless noted.
- Unit tests run with: `docker compose exec web python -m pytest`
- The web container service is `web`; the app code is mounted at `/app` (host `app/`).
- Coverage gate is 90% on the `user_data` package (`app/pytest.ini`).

---

## Task 1: i18n settings and LanguageMiddleware

**Files:**
- Create: `app/etipitaka_auth/i18n.py`
- Modify: `app/etipitaka_auth/settings.py`
- Test: `app/user_data/tests/test_i18n.py`

- [ ] **Step 1: Write the failing test**

Create `app/user_data/tests/test_i18n.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `docker compose exec web python -m pytest user_data/tests/test_i18n.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'etipitaka_auth.i18n'`

- [ ] **Step 3: Create the middleware**

Create `app/etipitaka_auth/i18n.py`:

```python
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
```

- [ ] **Step 4: Update settings**

In `app/etipitaka_auth/settings.py`, change the `MIDDLEWARE` list to add the new middleware right after `SessionMiddleware`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'etipitaka_auth.i18n.LanguageMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

Replace the Internationalization block (the `LANGUAGE_CODE = 'en-us'` line and following) with:

```python
# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'th'

LANGUAGES = [
    ('th', 'ไทย'),
    ('en', 'English'),
]

LOCALE_PATHS = [os.path.join(BASE_DIR, 'locale')]

TIME_ZONE = 'Asia/Bangkok'

USE_I18N = True

USE_L10N = True

USE_TZ = True
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `docker compose exec web python -m pytest user_data/tests/test_i18n.py -v`
Expected: PASS — 3 tests pass.

- [ ] **Step 6: Run the full suite to confirm no regression**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass, coverage ≥ 90%.

- [ ] **Step 7: Commit**

```bash
git add app/etipitaka_auth/i18n.py app/etipitaka_auth/settings.py app/user_data/tests/test_i18n.py
git commit -m "feat: add LanguageMiddleware, Thai default i18n settings"
```

---

## Task 2: Language switcher and base.html markup

**Files:**
- Modify: `app/etipitaka_auth/urls.py`
- Modify: `app/templates/base.html`
- Test: `app/user_data/tests/test_i18n.py`

- [ ] **Step 1: Write the failing test**

Append to `app/user_data/tests/test_i18n.py`:

```python
def test_setlang_view_sets_cookie_and_redirects(client):
    response = client.post('/i18n/setlang/',
                           {'language': 'en', 'next': '/login/'})
    assert response.status_code == 302
    assert client.cookies[settings.LANGUAGE_COOKIE_NAME].value == 'en'
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `docker compose exec web python -m pytest user_data/tests/test_i18n.py::test_setlang_view_sets_cookie_and_redirects -v`
Expected: FAIL — 404, the `/i18n/setlang/` route does not exist.

- [ ] **Step 3: Add the switcher route**

In `app/etipitaka_auth/urls.py`, add the import and the route. The imports block becomes:

```python
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView
from django.views.i18n import set_language

from user_data import views, auth_views
from user_data.auth_urls import rest_auth_patterns
```

Add this entry to `urlpatterns`, immediately before the `path('admin/', ...)` line:

```python
    path('i18n/setlang/', set_language, name='set_language'),
```

- [ ] **Step 4: Update base.html**

Replace the entire contents of `app/templates/base.html` with:

```html
{% load static i18n %}
{% get_current_language as CURRENT_LANG %}
<!DOCTYPE html>
<html lang="{{ CURRENT_LANG }}" ng-app="EtipitakaUserDataApp">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% block title %}{% trans "E-Tipitaka User Data" %}{% endblock %}</title>

    <!-- Bootstrap -->
    <link href="{% static "bootstrap/dist/css/bootstrap.min.css" %}" rel="stylesheet">
    <link href="{% static "bootstrap/dist/css/bootstrap-theme.min.css" %}" rel="stylesheet">
    <link href="{% static "angular-bootstrap/ui-bootstrap-csp.css" %}" rel="stylesheet">
    <link href="{% static "css-spinners/css/spinners.css" %}" rel="stylesheet">
    {% block style %}{% endblock %}

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
    <style type="text/css">
        .checkbox-list { border:2px solid #ccc; width:300px; height: 350px; overflow-y: scroll; }
    </style>
  </head>
  <body>
<nav class="navbar navbar-default">
  <div class="container">
    <!-- Brand and toggle get grouped for better mobile display -->
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">
        <span class="sr-only">{% trans "Toggle navigation" %}</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="/">{% trans "Home" %}</a>
    </div>

    <!-- Collect the nav links, forms, and other content for toggling -->
    <div class="collapse navbar-collapse" id="navbar-main">
      <form class="navbar-form navbar-left" action="{% url 'set_language' %}" method="post">
        {% csrf_token %}
        <input name="next" type="hidden" value="{{ request.path }}">
        {% if CURRENT_LANG == 'th' %}
        <button type="submit" name="language" value="en" class="btn btn-link">English</button>
        {% else %}
        <button type="submit" name="language" value="th" class="btn btn-link">ไทย</button>
        {% endif %}
      </form>
      {% if user.is_authenticated %}
      <form class="navbar-form navbar-right" method="post" action="/account/logout/">
        {% csrf_token %}
        <span ng-controller="UserDataController" class="btn btn-primary" ng-click="upload()">{% trans "Upload" %}</span>
        <button type="submit" class="btn btn-default">{% trans "Logout" %}</button>
        &nbsp;&nbsp;
        <span class="glyphicon glyphicon-user" aria-hidden="true"></span>
        <span class="label label-info">{{user}}</span>
      </form>
      {% else %}
      <ul class="nav navbar-nav navbar-right">
        <li><a href="/login/">{% trans "Login" %}</a></li>
        <li><a href="/signup/">{% trans "Register" %}</a></li>
      </ul>
      {% endif %}
    </div><!-- /.navbar-collapse -->


  </div><!-- /.container-fluid -->
</nav>
    {% block body %}{% endblock %}
    <script>
      window.i18n = {
        confirmDelete: "{% trans 'Are you sure?' %}",
        passwordTooShort: "{% trans 'password is too short' %}",
        passwordsNotMatch: "{% trans 'passwords not match' %}"
      };
    </script>
    <script src="{% static "jquery/dist/jquery.min.js" %}"></script>
    <script src="{% static "bootstrap/dist/js/bootstrap.min.js" %}"></script>
    <script src="{% static "angular/angular.min.js" %}"></script>
    <script src="{% static "angular-bootstrap/ui-bootstrap.min.js" %}"></script>
    <script src="{% static "angular-bootstrap/ui-bootstrap-tpls.min.js" %}"></script>
    <script src="{% static "ng-file-upload-shim/ng-file-upload-shim.min.js" %}"></script>
    <script src="{% static "ng-file-upload/ng-file-upload.min.js" %}"></script>
    <script src="{% static "moment/moment.js" %}"></script>
    <script src="{% static "bootbox.js/bootbox.js" %}"></script>
    <script src="{% static "app.js" %}"></script>
    {% block script %}{% endblock %}
  </body>
</html>
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `docker compose exec web python -m pytest user_data/tests/test_i18n.py -v`
Expected: PASS — 4 tests pass.

- [ ] **Step 6: Confirm no regression**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass.

- [ ] **Step 7: Commit**

```bash
git add app/etipitaka_auth/urls.py app/templates/base.html app/user_data/tests/test_i18n.py
git commit -m "feat: add language switcher route and i18n markup in base.html"
```

---

## Task 3: Wrap page templates with trans tags

No catalog exists yet, so every `{% trans %}` returns its English msgid — pages
still render in English and the existing behavioral tests still pass. Thai text
arrives in Task 7.

**Files:**
- Modify: `app/templates/index.html`, `login.html`, `signup.html`, `validate.html`, `user_data.html`
- Modify: `app/templates/registration/password_reset_form.html`, `password_reset_done.html`, `password_reset_confirm.html`, `password_reset_complete.html`

- [ ] **Step 1: Wrap `index.html`**

Replace `app/templates/index.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block body %}
<div class="container">
    <h1>{% trans "E-Tipitaka User Data" %}</h1>
    <br/>
    <p>{% blocktrans %}Welcome anonymous user!
      You need to <a href="/login">Login</a>
      before you can use this application.{% endblocktrans %}</p>
    <p>{% blocktrans %}If you don't have an account, please <a href="/signup/">Register now!</a>{% endblocktrans %}</p>
</div>
{% endblock %}
```

- [ ] **Step 2: Wrap `login.html`**

Replace `app/templates/login.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Login" %}{% endblock %}

{% block body %}
<div class="container">
    <h1>{% trans "Login" %}</h1>
    <br/>
    {% include "forms/login_form.html" %}
</div>
{% endblock %}
```

- [ ] **Step 3: Wrap `signup.html`**

Replace `app/templates/signup.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Registration" %}{% endblock %}

{% block body %}
<div ng-controller="RegisterController" class="container">
    <h1>{% trans "Registration" %}</h1>
    <br/>
    <script type="text/ng-template" id="loadingModalContent.html">
        <div class="modal-body" style="text-align:center;">
            <div class="spinner-loader" style="text-align:center;">
                {% trans "Loading..." %}
            </div>
            <div style="text-align:center">
                {% trans "Loading..." %}
            </div>
        </div>
    </script>
    {% include "forms/signup_form.html" %}
</div>
{% endblock %}
```

- [ ] **Step 4: Wrap `validate.html`**

Replace `app/templates/validate.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Validate your e-mail" %}{% endblock %}

{% block body %}
<div class="container">
    <h1>{% trans "Validate your e-mail" %}</h1>
    <br/>
    <p>
    <span class="label label-success">{% trans "Your registration was successful!" %}</span>
    </p>
    <p>
    {% trans "Please check your inbox for an e-mail containing instructions on validating your e-mail address." %}
    </p>
    <p>
    {% blocktrans %}If you do not receive an e-mail within 5-10 minutes, please try <a href="/signup/">registering your account</a> again.{% endblocktrans %}
    </p>
</div>
{% endblock %}
```

- [ ] **Step 5: Wrap `user_data.html`**

Replace `app/templates/user_data.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block body %}
<div ng-controller="UserDataController" class="container" data-ng-init="init()">
    <script type="text/ng-template" id="uploadModalContent.html">
        <div class="modal-header">
            <h3>{% trans "Upload data file" %}</h3>
        </div>
        <div class="modal-body">
           <button class="btn btn-default" type="file"
                   ngf-max-size="2MB"
                   ngf-select="uploadFiles($file, $invalidFiles, '{{csrf_token}}')"
                   ngf-accept="'.js,.etz,.json'">{% trans "Select File" %}</button> &nbsp;
            <span class="label label-success" ng-show="progress==100&&success"> {% trans "Upload completed" %} </span>
            <span class="label label-danger" ng-show="progress==100&&fileExists"> {% trans "File already exists" %} </span>
            <br/><br/>
            {% trans "File:" %} {{f.name}}
            <div class="progress" ng-show="progress>0">
              <div class="progress-bar" role="progressbar" aria-valuenow="<[progress]>" aria-valuemin="0" aria-valuemax="100" style="width: <[progress]>%;">
                <[progress]>%
              </div>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-primary" type="button" ng-click="close()">{% trans "Close" %}</button>
        </div>
    </script>

    <h1>{% trans "E-Tipitaka User Data" %}</h1>
    <br/>
    <div class="container">
        <!-- Nav tabs -->
        <ul class="nav nav-tabs" role="tablist">
            <li role="presentation" class="active">
                <a href="#ios" aria-controls="ios" role="tab" data-toggle="tab">iOS</a>
            </li>
            <li role="presentation">
                <a href="#android" aria-controls="android" role="tab" data-toggle="tab">Android</a>
            </li>
            <li role="presentation">
                <a href="#pc" aria-controls="pc" role="tab" data-toggle="tab">PC</a>
            </li>
            <li role="presentation">
                <a href="#share" aria-controls="share" role="tab" data-toggle="tab">{% trans "Share" %}</a>
            </li>
        </ul>
        <!-- Tab panes -->
        <div class="tab-content">
            <div role="tabpanel" class="tab-pane active" id="ios">
                <table class="table table-striped table-hover">
                    {% include "fragments/table_header.html" %}
                    <tbody>
                        <tr ng-repeat="item in $root.items | filter: ios | orderBy: '-pk' track by $index">
                            {% include "fragments/table_body.html" %}
                        </tr>
                    </tbody>
                </table>
            </div>
            <div role="tabpanel" class="tab-pane" id="android">
                <table class="table table-striped table-hover">
                    {% include "fragments/table_header.html" %}
                    <tbody>
                        <tr ng-repeat="item in $root.items | filter: android | orderBy: '-pk' track by $index">
                            {% include "fragments/table_body.html" %}
                        </tr>
                    </tbody>
                </table>
            </div>
            <div role="tabpanel" class="tab-pane" id="pc">
                <table class="table table-striped table-hover">
                    {% include "fragments/table_header.html" %}
                    <tbody>
                        <tr ng-repeat="item in $root.items | filter: pc | orderBy: '-pk' track by $index">
                            {% include "fragments/table_body.html" %}
                        </tr>
                    </tbody>
                </table>
            </div>
            <div role="tabpanel" class="tab-pane" id="share">
                <b>{% trans "Select user" %}</b>
                <div class="row">
                    <div class="checkbox-list">
                        <div ng-repeat="item in $root.sharingList">
                            <input type="checkbox" ng-model="$root.sharing[item.pk]" ng-change="changeSharing(item.pk, '{{csrf_token}}')" /> <[item.username]>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
```

- [ ] **Step 6: Wrap `registration/password_reset_form.html`**

Replace `app/templates/registration/password_reset_form.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Reset password" %}{% endblock %}

{% block body %}
<div class="container">
    <h1>{% trans "Reset your password" %}</h1>
    <br/>
    <p>{% trans "Enter your account email address and we'll send you a link to reset your password." %}</p>
    <form class="form-horizontal" method="post" action="">{% csrf_token %}
      {% if form.errors %}
      <div class="form-group row">
        <div class="col-sm-offset-2 col-sm-10">
          <span class="error-msg">{% trans "Please enter a valid email address." %}</span>
        </div>
      </div>
      {% endif %}

      <div class="form-group row">
        <label for="email" class="col-sm-2 control-label">{% trans "Email" %}</label>
        <div class="col-sm-6">
          <input required name="email" type="email" class="form-control" id="email" placeholder="{% trans 'Email' %}">
        </div>
      </div>

      <div class="form-group row">
        <div class="col-sm-offset-2 col-sm-10">
          <button type="submit" class="btn btn-default">{% trans "Send reset link" %}</button>
        </div>
      </div>
    </form>
</div>
{% endblock %}
```

- [ ] **Step 7: Wrap `registration/password_reset_done.html`**

Replace `app/templates/registration/password_reset_done.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Password reset sent" %}{% endblock %}

{% block body %}
<div class="container">
    <h1>{% trans "Check your email" %}</h1>
    <br/>
    <p>
    <span class="label label-success">{% trans "Password reset email sent." %}</span>
    </p>
    <p>
    {% trans "If an account exists for the email you entered, you will receive a message with instructions to reset your password shortly." %}
    </p>
    <p>
    {% blocktrans %}If you do not receive an email within a few minutes, check your spam folder
    or <a href="/password_reset/">try again</a>.{% endblocktrans %}
    </p>
    <p><a href="/login/">{% trans "Back to login" %}</a></p>
</div>
{% endblock %}
```

- [ ] **Step 8: Wrap `registration/password_reset_confirm.html`**

Replace `app/templates/registration/password_reset_confirm.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Set new password" %}{% endblock %}

{% block body %}
<div class="container">
    <h1>{% trans "Set a new password" %}</h1>
    <br/>
    {% if validlink %}
    <form class="form-horizontal" method="post" action="">{% csrf_token %}
      {% if form.errors %}
      <div class="form-group row">
        <div class="col-sm-offset-2 col-sm-10">
          {% for field in form %}{% for error in field.errors %}
          <span class="error-msg">{{ error }}</span><br/>
          {% endfor %}{% endfor %}
        </div>
      </div>
      {% endif %}

      <div class="form-group row">
        <label for="new_password1" class="col-sm-2 control-label">{% trans "New password" %}</label>
        <div class="col-sm-6">
          <input required name="new_password1" type="password" class="form-control" id="new_password1">
        </div>
      </div>

      <div class="form-group row">
        <label for="new_password2" class="col-sm-2 control-label">{% trans "Repeat password" %}</label>
        <div class="col-sm-6">
          <input required name="new_password2" type="password" class="form-control" id="new_password2">
        </div>
      </div>

      <div class="form-group row">
        <div class="col-sm-offset-2 col-sm-10">
          <button type="submit" class="btn btn-default">{% trans "Change password" %}</button>
        </div>
      </div>
    </form>
    {% else %}
    <p>
    <span class="label label-danger">{% trans "This password reset link is invalid or has expired." %}</span>
    </p>
    <p>
    {% blocktrans %}It may have already been used. Please
    <a href="/password_reset/">request a new reset link</a>.{% endblocktrans %}
    </p>
    {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 9: Wrap `registration/password_reset_complete.html`**

Replace `app/templates/registration/password_reset_complete.html` with:

```html
{% extends 'base.html' %}

{% load static i18n %}

{% block title %}{% trans "Password reset complete" %}{% endblock %}

{% block body %}
<div class="container">
    <h1>{% trans "Password reset complete" %}</h1>
    <br/>
    <p>
    <span class="label label-success">{% trans "Your password has been changed." %}</span>
    </p>
    <p>{% blocktrans %}You can now <a href="/login/">log in</a> with your new password.{% endblocktrans %}</p>
</div>
{% endblock %}
```

- [ ] **Step 10: Run the suite to confirm pages still render (English)**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass; templates render English msgids since no catalog exists yet.

- [ ] **Step 11: Commit**

```bash
git add app/templates/index.html app/templates/login.html app/templates/signup.html app/templates/validate.html app/templates/user_data.html app/templates/registration/
git commit -m "feat: wrap page templates with i18n trans tags"
```

---

## Task 4: Wrap fragments and the verification email template

**Files:**
- Modify: `app/templates/forms/login_form.html`, `forms/signup_form.html`
- Modify: `app/templates/fragments/table_header.html`, `fragments/table_body.html`
- Modify: `app/templates/email/verify_email.txt`

- [ ] **Step 1: Wrap `forms/login_form.html`**

Replace `app/templates/forms/login_form.html` with:

```html
{% load i18n %}
<div>
<form class="form-horizontal" id="signup" role="form" method="post" action="/login/">{% csrf_token %}
  {% if confirm_email %}
  <div class="form-group row">
    <div class="col-sm-offset-2 col-sm-10">
      <span class="label label-success">{% trans "Your email has been validated. You can login now." %}</span>
    </div>
  </div>
  {% endif %}

  <div class="form-group row">
    <label for="username" class="col-sm-2 control-label">{% trans "Username" %}</label>
    <div class="col-sm-6">
      <input required name="username" type="text" class="form-control" id="username" placeholder="{% trans 'Username' %}">
    </div>
  </div>

  <div class="form-group row">
    <label for="password1" class="col-sm-2 control-label">{% trans "Password" %}</label>
    <div class="col-sm-6">
      <input required name="password" type="password" class="form-control" id="password" placeholder="{% trans 'Password' %}">
    </div>
  </div>

  {% if invalid_login %}
  <div class="form-group row">
    <div class="col-sm-offset-2 col-sm-10">
        {% blocktrans %}Sorry, unrecognized username or password. <a href="/password_reset/">Have you forgotten your password?</a>{% endblocktrans %}
    </div>
  </div>
  {% endif %}

  {% if disabled_account %}
  <div class="form-group row">
    <div class="col-sm-offset-2 col-sm-10">
        {% trans "Sorry, your account has been blocked." %}
    </div>
  </div>
  {% endif %}

  <div class="form-group row">
    <div class="col-sm-offset-2 col-sm-10">
      <button type="submit" class="btn btn-default">{% trans "Login" %}</button>
    </div>
  </div>
</form>
</div>
```

- [ ] **Step 2: Wrap `forms/signup_form.html`**

Replace `app/templates/forms/signup_form.html` with:

```html
{% load i18n %}
<div>
<form class="form-horizontal" id="signup" role="form">
  <div class="form-group row">
    <label for="email" class="col-sm-2 control-label">{% trans "Email" %}</label>
    <div class="col-sm-6">
      <input required ng-model="inputForm.email" name="email" type="email" class="form-control" id="email" placeholder="{% trans 'Email' %}">
    </div>
    <span class="col-sm-4" class="error-msg"><[error.email]></span>
  </div>

  <div class="form-group row">
    <label for="username" class="col-sm-2 control-label">{% trans "Username" %}</label>
    <div class="col-sm-6">
      <input required ng-model="inputForm.username" name="username" type="text" class="form-control" id="username" placeholder="{% trans 'Username' %}">
    </div>
    <span class="col-sm-4" class="error-msg"><[error.username]></span>
  </div>

  <div class="form-group row">
    <label for="password1" class="col-sm-2 control-label">{% trans "Password" %}</label>
    <div class="col-sm-6">
      <input required ng-model="inputForm.password1" name="password1" type="password" class="form-control" id="password1" placeholder="{% trans 'Password' %}">
    </div>
  </div>

  <div class="form-group row">
    <label for="password2" class="col-sm-2 control-label">{% trans "Repeat password" %}</label>
    <div class="col-sm-6">
      <input required ng-model="inputForm.password2" name="password2" type="password" class="form-control" id="password2" placeholder="{% trans 'Repeat password' %}">
    </div>
    <span class="col-sm-4" class="error-msg"><[error.password]></span>
  </div>

  <div class="form-group row">
    <div class="col-sm-offset-2 col-sm-10">
      <button type="submit" class="btn btn-default" ng-click="signup('{% url 'rest_auth:rest_register' %}')">{% trans "Sign up" %}</button>
    </div>
  </div>
</form>
</div>
```

- [ ] **Step 3: Wrap `fragments/table_header.html`**

Replace `app/templates/fragments/table_header.html` with:

```html
{% load i18n %}
<thead>
    <tr>
        <th>#</th>
        <th>{% trans "Filename" %}</th>
        <th>{% trans "Created" %}</th>
        <th>{% trans "Action" %}</th>
    </tr>
</thead>
```

- [ ] **Step 4: Wrap `fragments/table_body.html`**

Replace `app/templates/fragments/table_body.html` with:

```html
{% load i18n %}
<td><[$index+1]></td>
<td><a href="/user_data/<[item.pk]>/"><[item.fields.file]></a></td>
<td><[formatDate(item.fields.created_at)]></td>
<td><button ng-click="delete(item.pk, '{{csrf_token}}')" type="button" class="btn btn-danger btn-xs">{% trans "Delete" %}</button></td>
```

- [ ] **Step 5: Wrap `email/verify_email.txt`**

Replace `app/templates/email/verify_email.txt` with:

```
{% load i18n %}{% blocktrans %}Hello {{ username }},

Please confirm your E-Tipitaka account email address by visiting the link below:

{{ verify_url }}

This link expires in 3 days. If you did not create this account, ignore this email.

-- E-Tipitaka{% endblocktrans %}
```

- [ ] **Step 6: Run the suite to confirm no regression**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass.

- [ ] **Step 7: Commit**

```bash
git add app/templates/forms/ app/templates/fragments/ app/templates/email/
git commit -m "feat: wrap form fragments and verification email with i18n tags"
```

---

## Task 5: Wrap Python strings with gettext

**Files:**
- Modify: `app/user_data/serializers.py`
- Modify: `app/user_data/auth_views.py`
- Modify: `app/user_data/forms.py`

- [ ] **Step 1: Wrap `serializers.py`**

In `app/user_data/serializers.py`, add the import at the top of the imports block:

```python
from django.utils.translation import gettext_lazy as _
```

Then wrap the four user-facing strings. The relevant lines become:

```python
            raise serializers.ValidationError(_("A user with that username already exists."))
```
```python
            raise serializers.ValidationError(_("A user with that email already exists."))
```
```python
            raise serializers.ValidationError({"password": _("The two password fields didn't match.")})
```

And in `LoginSerializer.validate`:

```python
        if user is None:
            raise serializers.ValidationError(
                {"non_field_errors": [_("Unable to log in with provided credentials.")]})
        if not user.is_active:
            raise serializers.ValidationError(
                {"non_field_errors": [_("This account is not active. Please verify your email.")]})
```

Leave the `validate_password` / `DjangoValidationError` branch unchanged — Django's password-validator messages are already translated by Django.

- [ ] **Step 2: Wrap `auth_views.py`**

In `app/user_data/auth_views.py`, add the import:

```python
from django.utils.translation import gettext as _
```

Wrap the email subject in `_send_verification_email`:

```python
    send_mail(_('Confirm your E-Tipitaka account'), body,
              settings.DEFAULT_FROM_EMAIL, [user.email])
```

Wrap the user-facing `detail` responses (leave the internal `{'detail': 'ok'}` unchanged):

```python
    return Response({'detail': _('Successfully logged out.')})
```
```python
    return Response({'detail': _('Verification e-mail sent.')},
                    status=status.HTTP_201_CREATED)
```
```python
        return Response({'detail': _('Invalid or expired token.')},
                        status=status.HTTP_400_BAD_REQUEST)
```

- [ ] **Step 3: Wrap `forms.py`**

Replace `app/user_data/forms.py` with:

```python
# -*- coding: utf-8 -*-
from django import forms
from django.utils.translation import gettext_lazy as _


class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField(
        label=_('Select a file'),
        help_text=_('max. 2 megabytes')
    )
```

- [ ] **Step 4: Run the suite to confirm no regression**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass. Strings still read English (no catalog yet).

- [ ] **Step 5: Commit**

```bash
git add app/user_data/serializers.py app/user_data/auth_views.py app/user_data/forms.py
git commit -m "feat: wrap Python user-facing strings with gettext"
```

---

## Task 6: Localize AngularJS strings via window.i18n

The `window.i18n` object is already injected by `base.html` (Task 2). This task
points `app.js` at it.

**Files:**
- Modify: `app/assets/app.js`

- [ ] **Step 1: Replace the hardcoded strings in `app.js`**

In `app/assets/app.js`, make these three edits.

The `delete` handler — replace:
```javascript
        bootbox.confirm("Are you sure?", function(result) {
```
with:
```javascript
        bootbox.confirm(window.i18n.confirmDelete, function(result) {
```

In `RegisterController.signup` — replace:
```javascript
                $scope.error.password = 'password is too short';
```
with:
```javascript
                $scope.error.password = window.i18n.passwordTooShort;
```

And replace:
```javascript
                $scope.error.password = 'passwords not match';
```
with:
```javascript
                $scope.error.password = window.i18n.passwordsNotMatch;
```

- [ ] **Step 2: Run the suite to confirm no regression**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass (no test exercises `app.js` directly).

- [ ] **Step 3: Commit**

```bash
git add app/assets/app.js
git commit -m "feat: localize AngularJS strings via window.i18n"
```

---

## Task 7: Generate, translate, and compile the Thai catalog

`makemessages` needs Django plus the GNU `gettext` binaries. The web container
has no `gettext`; the dev Mac has `gettext` on `PATH` (`/opt/homebrew/bin`) but
no Django. So the catalog is generated and compiled in a throwaway Python
virtualenv on the Mac, and the compiled `.mo` is committed.

**Files:**
- Create: `app/locale/th/LC_MESSAGES/django.po`
- Create: `app/locale/th/LC_MESSAGES/django.mo`

- [ ] **Step 1: Create the locale directory and a throwaway venv**

```bash
mkdir -p app/locale
python3 -m venv /tmp/i18nvenv
/tmp/i18nvenv/bin/pip install django==5.2.6
```

- [ ] **Step 2: Extract message ids**

```bash
cd app && /tmp/i18nvenv/bin/django-admin makemessages -l th -i 'assets/*' && cd ..
```

Expected: `app/locale/th/LC_MESSAGES/django.po` is created, containing every
`{% trans %}` / `gettext()` string with empty `msgstr ""` entries.

- [ ] **Step 3: Fill in the Thai translations**

Edit `app/locale/th/LC_MESSAGES/django.po`. For each entry, set `msgstr` from
this reference table (the `msgid` is the English source on the left). For
`#, fuzzy` flagged entries, remove the `fuzzy` flag after translating.

| msgid (English) | msgstr (Thai) |
|---|---|
| E-Tipitaka User Data | ข้อมูลผู้ใช้ E-Tipitaka |
| Toggle navigation | สลับเมนูนำทาง |
| Home | หน้าแรก |
| Upload | อัปโหลด |
| Logout | ออกจากระบบ |
| Login | เข้าสู่ระบบ |
| Register | สมัครสมาชิก |
| Are you sure? | ยืนยันการลบใช่หรือไม่? |
| password is too short | รหัสผ่านสั้นเกินไป |
| passwords not match | รหัสผ่านไม่ตรงกัน |
| Welcome anonymous user! You need to <a href="/login">Login</a> before you can use this application. | ยินดีต้อนรับผู้ใช้ที่ยังไม่ได้เข้าสู่ระบบ! คุณต้อง<a href="/login">เข้าสู่ระบบ</a>ก่อนจึงจะใช้งานแอปพลิเคชันนี้ได้ |
| If you don't have an account, please <a href="/signup/">Register now!</a> | หากคุณยังไม่มีบัญชี โปรด<a href="/signup/">สมัครสมาชิกเลย!</a> |
| Registration | สมัครสมาชิก |
| Loading... | กำลังโหลด... |
| Validate your e-mail | ยืนยันอีเมลของคุณ |
| Your registration was successful! | สมัครสมาชิกสำเร็จแล้ว! |
| Please check your inbox for an e-mail containing instructions on validating your e-mail address. | โปรดตรวจสอบกล่องจดหมายของคุณเพื่อดูอีเมลที่มีคำแนะนำในการยืนยันที่อยู่อีเมลของคุณ |
| If you do not receive an e-mail within 5-10 minutes, please try <a href="/signup/">registering your account</a> again. | หากคุณไม่ได้รับอีเมลภายใน 5-10 นาที โปรด<a href="/signup/">สมัครบัญชีของคุณ</a>อีกครั้ง |
| Upload data file | อัปโหลดไฟล์ข้อมูล |
| Select File | เลือกไฟล์ |
| Upload completed | อัปโหลดเสร็จสมบูรณ์ |
| File already exists | มีไฟล์นี้อยู่แล้ว |
| File: | ไฟล์: |
| Close | ปิด |
| Share | แชร์ |
| Select user | เลือกผู้ใช้ |
| Reset password | รีเซ็ตรหัสผ่าน |
| Reset your password | รีเซ็ตรหัสผ่านของคุณ |
| Enter your account email address and we'll send you a link to reset your password. | กรอกที่อยู่อีเมลของบัญชีคุณ แล้วเราจะส่งลิงก์สำหรับรีเซ็ตรหัสผ่านให้คุณ |
| Please enter a valid email address. | โปรดกรอกที่อยู่อีเมลที่ถูกต้อง |
| Email | อีเมล |
| Send reset link | ส่งลิงก์รีเซ็ต |
| Password reset sent | ส่งคำขอรีเซ็ตรหัสผ่านแล้ว |
| Check your email | ตรวจสอบอีเมลของคุณ |
| Password reset email sent. | ส่งอีเมลรีเซ็ตรหัสผ่านแล้ว |
| If an account exists for the email you entered, you will receive a message with instructions to reset your password shortly. | หากมีบัญชีสำหรับอีเมลที่คุณกรอก คุณจะได้รับข้อความพร้อมคำแนะนำในการรีเซ็ตรหัสผ่านในไม่ช้า |
| If you do not receive an email within a few minutes, check your spam folder or <a href="/password_reset/">try again</a>. | หากคุณไม่ได้รับอีเมลภายในไม่กี่นาที โปรดตรวจสอบโฟลเดอร์สแปม หรือ<a href="/password_reset/">ลองอีกครั้ง</a> |
| Back to login | กลับไปหน้าเข้าสู่ระบบ |
| Set new password | ตั้งรหัสผ่านใหม่ |
| Set a new password | ตั้งรหัสผ่านใหม่ |
| New password | รหัสผ่านใหม่ |
| Repeat password | ยืนยันรหัสผ่าน |
| Change password | เปลี่ยนรหัสผ่าน |
| This password reset link is invalid or has expired. | ลิงก์รีเซ็ตรหัสผ่านนี้ไม่ถูกต้องหรือหมดอายุแล้ว |
| It may have already been used. Please <a href="/password_reset/">request a new reset link</a>. | ลิงก์นี้อาจถูกใช้ไปแล้ว โปรด<a href="/password_reset/">ขอลิงก์รีเซ็ตใหม่</a> |
| Password reset complete | รีเซ็ตรหัสผ่านเสร็จสมบูรณ์ |
| Your password has been changed. | เปลี่ยนรหัสผ่านของคุณเรียบร้อยแล้ว |
| You can now <a href="/login/">log in</a> with your new password. | ตอนนี้คุณสามารถ<a href="/login/">เข้าสู่ระบบ</a>ด้วยรหัสผ่านใหม่ของคุณได้แล้ว |
| Your email has been validated. You can login now. | ยืนยันอีเมลของคุณเรียบร้อยแล้ว คุณสามารถเข้าสู่ระบบได้ทันที |
| Username | ชื่อผู้ใช้ |
| Password | รหัสผ่าน |
| Sorry, unrecognized username or password. <a href="/password_reset/">Have you forgotten your password?</a> | ขออภัย ไม่พบชื่อผู้ใช้หรือรหัสผ่านนี้ <a href="/password_reset/">คุณลืมรหัสผ่านหรือไม่?</a> |
| Sorry, your account has been blocked. | ขออภัย บัญชีของคุณถูกระงับการใช้งาน |
| Sign up | สมัครสมาชิก |
| Filename | ชื่อไฟล์ |
| Created | วันที่สร้าง |
| Action | การจัดการ |
| Delete | ลบ |
| A user with that username already exists. | มีผู้ใช้ที่ใช้ชื่อผู้ใช้นี้อยู่แล้ว |
| A user with that email already exists. | มีผู้ใช้ที่ใช้อีเมลนี้อยู่แล้ว |
| The two password fields didn't match. | รหัสผ่านทั้งสองช่องไม่ตรงกัน |
| Unable to log in with provided credentials. | ไม่สามารถเข้าสู่ระบบด้วยข้อมูลที่ให้มาได้ |
| This account is not active. Please verify your email. | บัญชีนี้ยังไม่เปิดใช้งาน โปรดยืนยันอีเมลของคุณ |
| Confirm your E-Tipitaka account | ยืนยันบัญชี E-Tipitaka ของคุณ |
| Successfully logged out. | ออกจากระบบเรียบร้อยแล้ว |
| Verification e-mail sent. | ส่งอีเมลยืนยันแล้ว |
| Invalid or expired token. | โทเค็นไม่ถูกต้องหรือหมดอายุ |
| Select a file | เลือกไฟล์ |
| max. 2 megabytes | ขนาดสูงสุด 2 เมกะไบต์ |

The `verify_email.txt` body is a single multi-line `blocktrans`. Its `msgid`
spans the whole message with `%(verify_url)s` / `%(username)s` placeholders;
translate it as:

```
msgid ""
"Hello %(username)s,\n"
"\n"
"Please confirm your E-Tipitaka account email address by visiting the link "
"below:\n"
"\n"
"%(verify_url)s\n"
"\n"
"This link expires in 3 days. If you did not create this account, ignore this "
"email.\n"
"\n"
"-- E-Tipitaka"
msgstr ""
"สวัสดี %(username)s\n"
"\n"
"โปรดยืนยันที่อยู่อีเมลของบัญชี E-Tipitaka ของคุณโดยเปิดลิงก์ด้านล่างนี้:\n"
"\n"
"%(verify_url)s\n"
"\n"
"ลิงก์นี้จะหมดอายุใน 3 วัน หากคุณไม่ได้สร้างบัญชีนี้ โปรดเพิกเฉยต่ออีเมลนี้\n"
"\n"
"-- E-Tipitaka"
```

(Match the exact `msgid` text that `makemessages` produced — copy its line
breaks and wrapping, only fill `msgstr`.)

Also set the `.po` header `Content-Type` to `text/plain; charset=UTF-8` if
`makemessages` left it as `CHARSET`.

- [ ] **Step 4: Compile the catalog**

```bash
cd app && /tmp/i18nvenv/bin/django-admin compilemessages -l th && cd ..
```

Expected: `app/locale/th/LC_MESSAGES/django.mo` is created. (`compilemessages`
invokes `msgfmt` from `/opt/homebrew/bin`.)

- [ ] **Step 5: Restart the web container and verify Thai renders**

```bash
docker compose restart web
curl -s http://localhost:1338/login/ | grep -o '<h1>[^<]*</h1>'
```

Expected: `<h1>เข้าสู่ระบบ</h1>` — the default (no cookie) page is Thai.

```bash
curl -s --cookie 'django_language=en' http://localhost:1338/login/ | grep -o '<h1>[^<]*</h1>'
```

Expected: `<h1>Login</h1>` — the English cookie still yields English.

- [ ] **Step 6: Commit**

```bash
git add app/locale/th/LC_MESSAGES/django.po app/locale/th/LC_MESSAGES/django.mo
git commit -m "feat: add compiled Thai message catalog"
```

The unit suite (`docker compose exec web python -m pytest`) still passes —
unit tests run with the test settings and assert behavior, not localized
copy. The golden harness and behavioral tests are updated in Task 8.

---

## Task 8: Update the golden harness and behavioral tests

Localization changes two test surfaces: the `test_behavioral.py` HTML-content
assertions (the default page is now Thai) and one golden snapshot
(`rest_login_bad`, whose JSON body carries the now-Thai
"Unable to log in..." error). All other golden cases return non-localized JSON
/ files / tokens and stay valid as cross-stack checks.

**Files:**
- Modify: `tests/golden/test_behavioral.py`
- Modify: `tests/golden/snapshots/rest_login_bad.json`
- Modify: `tests/golden/README.md`

- [ ] **Step 1: Update the behavioral HTML-content assertions**

In `tests/golden/test_behavioral.py`, update the markers in these tests to the
Thai default text.

`test_index_page_renders` — replace:
```python
    assert "E-Tipitaka User Data" in resp.text
```
with:
```python
    assert "ข้อมูลผู้ใช้ E-Tipitaka" in resp.text
```

`test_login_page_renders` — replace:
```python
    assert "<h1>Login</h1>" in resp.text
```
with:
```python
    assert "<h1>เข้าสู่ระบบ</h1>" in resp.text
```

`test_signup_page_renders` — replace:
```python
    assert "<h1>Registration</h1>" in resp.text
```
with:
```python
    assert "<h1>สมัครสมาชิก</h1>" in resp.text
```

`test_validate_page_renders` — replace:
```python
    assert "Validate your e-mail" in resp.text
```
with:
```python
    assert "ยืนยันอีเมลของคุณ" in resp.text
```

`test_password_reset_pages_use_project_templates` — replace the `pages` list:
```python
    pages = [
        ("/password_reset/", "Reset your password"),
        ("/password_reset/done/", "Check your email"),
        ("/reset/done/", "Password reset complete"),
        ("/reset/baduid/badtoken/", "Set a new password"),
    ]
```
with:
```python
    pages = [
        ("/password_reset/", "รีเซ็ตรหัสผ่านของคุณ"),
        ("/password_reset/done/", "ตรวจสอบอีเมลของคุณ"),
        ("/reset/done/", "รีเซ็ตรหัสผ่านเสร็จสมบูรณ์"),
        ("/reset/baduid/badtoken/", "ตั้งรหัสผ่านใหม่"),
    ]
```

The CSRF-token regex in `test_web_login_through_nginx_succeeds` and the
`"Django site admin"` negative assertion are language-independent — leave them
unchanged.

- [ ] **Step 2: Re-run the behavioral suite to confirm it passes**

```bash
docker compose up -d
docker compose exec web python manage.py seed_golden
. tests/golden/.venv/bin/activate
pytest tests/golden/test_behavioral.py -v --base-url http://localhost:1338
deactivate
```

Expected: PASS — all behavioral tests pass against the localized stack.

- [ ] **Step 3: Re-record the affected golden snapshot**

The `rest_login_bad` case returns the localized login error. Re-record only
that snapshot against the new (localized) stack:

```bash
. tests/golden/.venv/bin/activate
pytest tests/golden/test_golden.py --record --base-url http://localhost:1338 -k rest_login_bad
deactivate
```

Expected: `tests/golden/snapshots/rest_login_bad.json` is rewritten; its body
now contains the Thai "ไม่สามารถเข้าสู่ระบบ..." message.

- [ ] **Step 4: Run the full golden suite to confirm green**

```bash
. tests/golden/.venv/bin/activate
pytest tests/golden -v --base-url http://localhost:1338
deactivate
```

Expected: PASS — all golden + behavioral + normalizer tests pass.

- [ ] **Step 5: Update the golden README**

In `tests/golden/README.md`, add this section after the `## Assert` section:

```markdown
## Localization note

The site is localized (Thai default, English via the `django_language`
cookie). Two surfaces are no longer cross-stack equivalent with the old
English-only stack and are intentionally same-stack:

- `test_behavioral.py` HTML-content assertions check the Thai default copy.
- The `rest_login_bad` golden snapshot carries the Thai login-error message.

All other golden snapshots (JSON data, tokens, file downloads, status codes)
are not localized and remain valid cross-stack regression checks.
```

- [ ] **Step 6: Commit**

```bash
git add tests/golden/test_behavioral.py tests/golden/snapshots/rest_login_bad.json tests/golden/README.md
git commit -m "test: update behavioral and golden tests for Thai localization"
```

---

## Task 9: Final verification

- [ ] **Step 1: Run the full unit suite**

Run: `docker compose exec web python -m pytest`
Expected: PASS — all tests pass, coverage ≥ 90%.

- [ ] **Step 2: Run the full golden harness**

```bash
docker compose up -d
docker compose exec web python manage.py seed_golden
. tests/golden/.venv/bin/activate
pytest tests/golden -v --base-url http://localhost:1338
deactivate
```
Expected: PASS — golden + behavioral + normalizer tests all green.

- [ ] **Step 3: Manual smoke check in a browser**

Open `http://localhost:1338/` in a fresh browser session (no cookie).
- The page renders in Thai.
- The navbar shows an `English` switch button.
- Clicking `English` reloads the page in English and the button now reads `ไทย`.
- Visit `/login/`, `/signup/`, `/signup/validate/`, `/password_reset/` — each renders Thai by default.

- [ ] **Step 4: Clean up the throwaway venv**

```bash
rm -rf /tmp/i18nvenv
```

---

## Notes for the implementer

- The web Docker image has no `gettext` binary by design (apt was removed in a
  prior session). Never add a build step that runs `makemessages` /
  `compilemessages` inside the `web` container. The committed `.mo` is all the
  runtime needs.
- `{% trans %}` with no catalog returns the English `msgid` verbatim, so Tasks
  3–6 leave the site working in English; Thai appears only after Task 7.
- After editing `app/templates/...` or `app.js`, no rebuild is needed — the
  `app/` directory is bind-mounted. After adding or recompiling the `.mo`,
  restart the `web` container so Django reloads the catalog.
- Django ships Thai translations for admin, auth password validators, DRF
  default errors, and the built-in password-reset *emails* — those need no
  work and are out of scope.
