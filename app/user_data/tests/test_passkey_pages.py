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
