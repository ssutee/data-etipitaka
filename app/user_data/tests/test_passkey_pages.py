import pytest

pytestmark = pytest.mark.django_db


def test_base_has_hidden_rule_and_passkey_i18n(client):
    html = client.get('/login/').content.decode()
    assert '[hidden] { display: none !important; }' in html
    assert 'passkeyCancelled:' in html


def test_navbar_links_security_page_when_signed_in(client, alice):
    client.force_login(alice)
    assert 'href="/account/security/"' in client.get('/user_data/').content.decode()


def test_navbar_hides_security_link_when_signed_out(client):
    assert 'href="/account/security/"' not in client.get('/login/').content.decode()


def test_login_page_has_passkey_controls(client):
    html = client.get('/login/').content.decode()
    assert 'id="passkey-login-button"' in html
    assert 'autocomplete="username webauthn"' in html
    assert 'autocomplete="current-password"' in html
    assert '/static/passkey.js' in html
    assert '/static/passkey_login.js' in html


def test_login_page_passkey_box_hidden_by_default_and_non_bindable(client):
    # Progressive enhancement: server-rendered HTML always starts with the
    # box hidden (JS removes `hidden` only once it confirms
    # window.Passkey.supported); ng-non-bindable keeps AngularJS from ever
    # interpolating the error text passkey_login.js writes into it later.
    html = client.get('/login/').content.decode()
    marker = html.index('id="passkey-login"')
    tag_start = html.rindex('<div', 0, marker)
    tag_end = html.index('>', marker)
    tag = html[tag_start:tag_end]
    assert 'hidden' in tag
    assert 'ng-non-bindable' in tag


def test_login_page_password_login_still_works_with_passkey_box_present(client, alice):
    # With window.Passkey.supported false (or JS disabled entirely), the
    # passkey box stays hidden and the plain password form must keep working.
    resp = client.post('/login/', {'username': 'alice', 'password': 'alicepass123'})
    assert resp.status_code == 302
    assert resp['Location'] == '/'


def test_signup_page_has_passkey_form_and_password_fallback(client):
    html = client.get('/signup/').content.decode()
    assert 'id="passkey-signup-form"' in html
    assert 'id="password-signup"' in html
    assert 'id="show-password-signup"' in html
    assert '/static/passkey_signup.js' in html


def test_signup_page_passkey_box_hidden_by_default_and_non_bindable(client):
    # Progressive enhancement: server-rendered HTML always starts with the
    # passkey box hidden (JS removes `hidden` only once it confirms
    # window.Passkey.supported); ng-non-bindable keeps AngularJS from ever
    # interpolating the per-field error text passkey_signup.js writes later.
    html = client.get('/signup/').content.decode()
    marker = html.index('id="passkey-signup"')
    tag_start = html.rindex('<div', 0, marker)
    tag_end = html.index('>', marker)
    tag = html[tag_start:tag_end]
    assert 'hidden' in tag
    assert 'ng-non-bindable' in tag


def test_signup_page_password_form_visible_by_default(client):
    # With JS off or passkeys unsupported, the password signup form must be
    # visible -- and working -- rather than depend on a script to reveal it.
    html = client.get('/signup/').content.decode()
    marker = html.index('id="password-signup"')
    tag_start = html.rindex('<div', 0, marker)
    tag_end = html.index('>', marker)
    tag = html[tag_start:tag_end]
    assert 'hidden' not in tag
    assert 'id="signup"' in html
    assert 'name="password1"' in html


def test_signup_page_has_per_field_passkey_error_targets(client):
    # begin_signup/finish_signup can report a taken username *and* a taken
    # email at once ({'username': [...], 'email': [...]}); each needs its
    # own place next to the matching input so neither message is dropped.
    html = client.get('/signup/').content.decode()
    assert 'id="passkey-email-error"' in html
    assert 'id="passkey-username-error"' in html
    assert 'id="passkey-signup-error"' in html


def test_signup_page_fallback_link_does_not_navigate(client):
    # href="#" is only safe with JS's preventDefault -- assert the link
    # exists so a future edit that drops the handler is caught by
    # test_signup_page_has_passkey_form_and_password_fallback failing to
    # find the id, and here that it does not point anywhere real.
    html = client.get('/signup/').content.decode()
    marker = html.index('id="show-password-signup"')
    tag_start = html.rindex('<a', 0, marker)
    tag_end = html.index('>', marker)
    tag = html[tag_start:tag_end]
    assert 'href="#"' in tag


def test_security_page_requires_login(client):
    resp = client.get('/account/security/')
    assert resp.status_code == 302
    assert resp['Location'] == '/login/?next=/account/security/'


def test_security_page_renders(client, alice):
    client.force_login(alice)
    resp = client.get('/account/security/')
    html = resp.content.decode()
    assert resp.status_code == 200
    assert 'id="passkey-rows"' in html
    assert 'id="security" ng-non-bindable' in html
    assert 'csrfmiddlewaretoken' in html
    assert '/static/account_security.js' in html
    assert 'csrftoken' in resp.cookies
