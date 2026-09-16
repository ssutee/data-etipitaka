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
