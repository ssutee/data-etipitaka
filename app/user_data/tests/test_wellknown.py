"""Apple / Android passkey association files served at /.well-known/.

Both endpoints must be reachable with no authentication and no CSRF token
(they are fetched by the OS, not a browser session), must reject any
non-GET/HEAD method with 405, and must always answer as
`Content-Type: application/json` -- Apple refuses to parse the AASA file
served with any other content type.
"""
from django.test import Client

AASA = '/.well-known/apple-app-site-association'
ASSETLINKS = '/.well-known/assetlinks.json'


def test_apple_app_site_association(client, settings):
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    resp = client.get(AASA)
    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/json'
    assert resp.json() == {'webcredentials': {'apps': ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']}}


def test_apple_app_site_association_404_when_ios_app_ids_empty(client, settings):
    # An empty {'webcredentials': {'apps': []}} would actively tell iOS that
    # no app is associated with this domain -- worse than a plain 404, since
    # a previously-registered app could be de-associated by clearing the
    # setting. Not-found is the safe "unconfigured" answer.
    settings.PASSKEY_IOS_APP_IDS = []
    resp = client.get(AASA)
    assert resp.status_code == 404
    assert resp['Content-Type'] == 'application/json'


def test_assetlinks_json_404_when_android_unset(client, settings):
    settings.PASSKEY_ANDROID_PACKAGE = ''
    settings.PASSKEY_ANDROID_CERT_SHA256 = []
    resp = client.get(ASSETLINKS)
    assert resp.status_code == 404
    assert resp['Content-Type'] == 'application/json'


def test_assetlinks_404_when_package_set_but_fingerprints_empty(client, settings):
    # A partial rollout (package configured, fingerprints not yet set, or
    # vice versa below) is a realistic state, not just "both unset" -- the
    # guard is an `or`, and either half being empty must still 404 rather
    # than publish a config with an empty sha256_cert_fingerprints list.
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = []
    resp = client.get(ASSETLINKS)
    assert resp.status_code == 404
    assert resp['Content-Type'] == 'application/json'


def test_assetlinks_404_when_package_empty_but_fingerprints_set(client, settings):
    settings.PASSKEY_ANDROID_PACKAGE = ''
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    resp = client.get(ASSETLINKS)
    assert resp.status_code == 404
    assert resp['Content-Type'] == 'application/json'


def test_assetlinks_when_configured(client, settings):
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    resp = client.get(ASSETLINKS)
    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/json'
    assert resp.json() == [{
        'relation': ['delegate_permission/common.get_login_creds'],
        'target': {'namespace': 'android_app', 'package_name': 'com.watnapp.etipitaka',
                   'sha256_cert_fingerprints': ['AB:CD']}}]


def test_wellknown_rejects_post(client, settings):
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    assert client.post(AASA).status_code == 405
    assert client.post(ASSETLINKS).status_code == 405


def test_wellknown_rejects_put_and_delete(client, settings):
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    assert client.put(AASA).status_code == 405
    assert client.delete(AASA).status_code == 405
    assert client.put(ASSETLINKS).status_code == 405
    assert client.delete(ASSETLINKS).status_code == 405


def test_wellknown_allows_head(client, settings):
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    assert client.head(AASA).status_code == 200
    assert client.head(ASSETLINKS).status_code == 200


def test_wellknown_anonymous_no_csrf_required(settings):
    # enforce_csrf_checks=True would 403 any unsafe request missing a CSRF
    # token; GET/HEAD are always CSRF-exempt, so this proves these endpoints
    # need neither a login session nor a CSRF token to be read.
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    strict_client = Client(enforce_csrf_checks=True)
    assert strict_client.get(AASA).status_code == 200
    assert strict_client.get(ASSETLINKS).status_code == 200


def test_wellknown_rejects_post_with_405_not_csrf_403(settings):
    # The default `client` fixture has enforce_csrf_checks=False, so it
    # cannot tell a clean 405 (require_http_methods) apart from a CSRF 403
    # that CsrfViewMiddleware would raise first for a real, cookie-less POST.
    # These views must be reachable with no CSRF token at all, so they need
    # to be exempt from CSRF and let the method check produce 405 instead.
    settings.PASSKEY_IOS_APP_IDS = ['A6DJDJ7527.com.watnapp.E-Tipitaka-Plus']
    settings.PASSKEY_ANDROID_PACKAGE = 'com.watnapp.etipitaka'
    settings.PASSKEY_ANDROID_CERT_SHA256 = ['AB:CD']
    strict_client = Client(enforce_csrf_checks=True)
    assert strict_client.post(AASA).status_code == 405
    assert strict_client.post(ASSETLINKS).status_code == 405
