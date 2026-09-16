import re

import pytest

from .conftest import add_passkey

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


# --- pins the template <-> account_security.js contract, from the Task 20 review ---

# Every data-* attribute account_security.js reads off #security's dataset
# (t.never, t.synced, ..., t.passwordRequired). A typo in either the
# template's attribute name or the JS's dataset access currently renders
# "undefined" (or throws) with nothing failing -- pin the exact set here.
SECURITY_PAGE_DATA_ATTRS = [
    'never', 'synced', 'device-bound', 'rename', 'remove', 'rename-prompt',
    'has-password', 'no-password', 'password-required',
]


def test_security_page_data_attributes_are_all_non_empty(client, alice):
    client.force_login(alice)
    html = client.get('/account/security/').content.decode()
    marker = html.index('id="security"')
    tag_start = html.rindex('<div', 0, marker)
    tag_end = html.index('>', marker)
    tag = html[tag_start:tag_end]
    for attr in SECURITY_PAGE_DATA_ATTRS:
        found = re.search(r'data-%s="([^"]*)"' % re.escape(attr), tag)
        assert found, attr
        assert found.group(1).strip(), attr


# Every element id account_security.js's $() (a bare getElementById, no
# fallback) reads. A missing id fails silently at runtime -- a null deref
# inside a .then()/click handler -- rather than a template error.
SECURITY_PAGE_ELEMENT_IDS = [
    'security', 'passkey-rows', 'security-error', 'passkey-list-error',
    'passkey-empty', 'passkey-unsupported', 'add-passkey',
    'step-up-password', 'step-up-password-input', 'add-passkey-button',
    'password-status', 'remove-password', 'remove-password-input',
    'remove-password-button',
]


def test_security_page_has_every_element_id_the_script_touches(client, alice):
    client.force_login(alice)
    html = client.get('/account/security/').content.decode()
    for element_id in SECURITY_PAGE_ELEMENT_IDS:
        assert 'id="%s"' % element_id in html, element_id


@pytest.mark.parametrize('element_id', [
    'add-passkey', 'step-up-password', 'remove-password',
    'passkey-empty', 'passkey-unsupported',
])
def test_security_page_progressive_enhancement_starts_hidden(client, alice, element_id):
    # Same progressive-enhancement contract as
    # test_login_page_passkey_box_hidden_by_default_and_non_bindable /
    # the signup page's equivalent above: the server always renders these
    # hidden, and account_security.js un-hides only what P.supported and
    # the loaded state call for.
    client.force_login(alice)
    html = client.get('/account/security/').content.decode()
    marker = html.index('id="%s"' % element_id)
    tag_start = html.rindex('<', 0, marker)
    tag_end = html.index('>', marker)
    tag = html[tag_start:tag_end]
    assert 'hidden' in tag


def test_security_page_loads_passkey_js_before_account_security_js(client, alice):
    # account_security.js reads window.Passkey at IIFE time (`var P =
    # window.Passkey;`), so passkey.js -- which defines window.Passkey --
    # must be the earlier <script> tag on the page.
    client.force_login(alice)
    html = client.get('/account/security/').content.decode()
    assert html.index('/static/passkey.js') < html.index('/static/account_security.js')


def test_passkey_name_xss_payload_survives_clean_name_unescaped(auth_alice, alice, authenticator):
    # DRF's JSON renderer must NOT HTML-escape -- JSON isn't HTML, and
    # escaping it would corrupt every other API consumer's data.
    # clean_name() (passkey_service.py) only strips a narrow set of
    # Unicode control/format/private-use/unassigned categories; ordinary
    # ASCII markup passes straight through. So the real defence against a
    # malicious passkey name is entirely client-side: account_security.js
    # writes every name with textContent (see its cell() helper), never
    # innerHTML, into a container marked ng-non-bindable so AngularJS's
    # own <[ ]> interpolation cannot run it either. Mirrors test_oauth.py's
    # test_consent_page_never_interpolates_client_name, but for a JSON
    # endpoint where NOT escaping is the correct, intentional behaviour.
    payload = '<img src=x onerror=alert(1)><[7*7]>'
    add_passkey(alice, authenticator, name=payload)
    resp = auth_alice.get('/api/passkeys/')
    assert resp.status_code == 200
    assert resp.json()['passkeys'][0]['name'] == payload
    assert payload.encode() in resp.content
