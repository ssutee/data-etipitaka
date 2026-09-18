"""End-to-end check of passkeys against a running stack.

Runs inside the web container, so it can use the unit tests' software
authenticator and create and delete its own throwaway accounts:

    docker compose exec -T web python - http://web:8000 < tests/passkey_e2e.py

Flow: password login -> step-up -> link passkey -> passkey token login ->
/rest-auth/user/ -> browser passkey login carrying an OAuth authorize `next`
-> consent page -> desktop pairing approved -> desktop pairing refused ->
passkey step-up -> remove password -> last-passkey guard
-> passkey signup -> login refused until activated -> login -> account
recovery (request a reset email, follow it, create a new passkey, confirm
every pre-recovery credential is revoked and the recovering client is
signed in) -> the spent reset link.

The authenticator answers for the relying party the server advertises: origin
https://<rpId>, or http://localhost:1338 when a dev override sets rpId to
localhost. A same-minute rerun WILL hit the passkey throttle (429), even
against the default http://web:8000: PasskeyRateThrottle is per-client-IP
for anonymous calls (settings' 'passkey' rate, 20/min in dev), this script's
own anonymous passkey calls alone number around ten per run, and every run
shares one IP (the container's). If a run fails with a THROTTLED error (see
Client.json below), wait about 60s for the bucket to refill, then re-run --
don't just retry immediately, since that would only refill the bucket
further into the next window and mask whatever the original failure was.

Running against the default http://web:8000 talks straight to the `web`
container and bypasses nginx entirely, so none of the Task 23 rate-limit
zones are exercised. Running against http://localhost:1338 instead goes
through nginx and DOES exercise them -- and, because this script performs
several passkey ceremonies for one account in quick succession, may 429
there (see nginx.conf's @ratelimited_passkey / @ratelimited_passkey_manage
zones). Note that `localhost:1338` only means anything from wherever that
address is actually routable to nginx's published port -- e.g. the docker
host itself, not another `docker compose exec -T web` process (that
container's own loopback has no nginx on it, so it would just get
ConnectionRefused); this script also needs django.setup() and direct
Postgres access, so running it against localhost:1338 means running it
somewhere that has both, not necessarily inside a container at all.

Email capture for the recovery step: dev settings use the console email
backend, which just prints to whichever process handles the request -- and
that is never this script's own process. `docker compose exec` starts a new
OS process in the `web` container; the actual HTTP request this script
sends to /password_reset/ is handled by one of gunicorn's own worker
processes (this container's PID 1 and its forks), a *different* process
with its own memory, so a module-level django.core.mail.outbox populated
there is not visible here, and there is no docker socket or CLI inside the
container to go read that worker's stdout instead. So request_password_reset
below is the one step in this script that does NOT go over `base`'s HTTP:
it forces settings.EMAIL_BACKEND to locmem (via override_settings, scoped to
just that call) and dispatches the request in-process with django.test.Client
(this script already called django.setup(), so it can), then reads
django.core.mail.outbox directly. That still runs the real
password_reset_view / AccountRecoveryForm code -- just via Django's own
request dispatch instead of a socket -- and is the only way this script can
observe what mail was actually sent. Everything downstream of getting that
link (following it, and the recover begin/finish calls) goes over real HTTP
to `base`, exactly like the rest of this script. A real HTTP GET to
/password_reset/ still happens too (recover_account's first step below),
so the route and its form template are exercised over the wire, the same as
everything else here -- only the POST that actually triggers the email is
in-process. That also means this script's real-HTTP traffic never POSTs to
/password_reset/ or /reset/<uidb64>/<token>/, so nginx's reset_post_rl zone
(Task 23) is never exercised even when run against localhost:1338 -- it was
deliberately left that way (a POST there would only spend budget from a
5/min zone for no extra coverage; see recover_account's own comment).

Not covered here: recovery bypassing the passkey cap (PASSKEY_MAX_PER_USER,
currently 20). Proving that over real HTTP means filling one account with
20 passkeys first -- 20 more register ceremonies on top of everything else
this script already does to the same account, which would reliably trip
the passkey throttle (settings' 'passkey' rate, 20/min in dev, and nginx's
Task 23 zones when run through localhost:1338) for no extra confidence:
app/user_data/tests/test_recovery.py's test_passkey_recovery_bypasses_
passkey_cap already proves it through the real HTTP view with the cap
monkeypatched down to 1, and test_passkey_service.py's
test_recover_succeeds_at_the_cap proves it at the real default of 20,
neither of which needs a live server or real WebAuthn round trips.
"""
import base64
import contextlib
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'etipitaka_auth.settings')
import django  # noqa: E402

django.setup()

from django.contrib.auth.models import User  # noqa: E402
from django.core import mail  # noqa: E402
from django.test import Client as DjangoTestClient  # noqa: E402
from django.test import override_settings  # noqa: E402
from oauth2_provider.models import Application  # noqa: E402

from user_data.account_tokens import delete_user_sessions  # noqa: E402
from user_data.tests.soft_authenticator import SoftAuthenticator  # noqa: E402

PASSWORD = 'e2e-Passkey-' + secrets.token_hex(4)
REDIRECT = 'https://app.example/cb'
# RFC 7636 appendix B example challenge; the flow never exchanges the code.
PKCE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        self.token = None

    def call(self, method, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header('Accept', 'application/json')
        if body is not None:
            request.add_header('Content-Type', 'application/json')
        if self.token:
            request.add_header('Authorization', 'Token ' + self.token)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with self.opener.open(request, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def form(self, method, path, data=None, headers=None):
        """Like call(), but application/x-www-form-urlencoded -- the shape
        the OAuth authorize/token endpoints (plain Django/oauthlib forms,
        not DRF) expect. Every other endpoint in this script takes JSON via
        call()/json(); only get_oauth_access_token uses this.
        """
        encoded = urllib.parse.urlencode(data or {}).encode()
        request = urllib.request.Request(self.base + path, data=encoded, method=method)
        request.add_header('Accept', 'application/json')
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with self.opener.open(request, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def json(self, method, path, body=None, expect=200, headers=None):
        status, _headers, raw = self.call(method, path, body, headers)
        if status == 429 and expect != 429:
            # Every DRF endpoint this script's json() calls sits behind
            # PasskeyRateThrottle (see the module docstring's throttle
            # paragraph) -- flag this specific, common failure clearly
            # rather than let it read as some other assertion tripping,
            # which would send a rerun chasing the wrong cause.
            raise AssertionError(
                'THROTTLED: %s %s -> 429 %s (wait ~60s for the passkey rate '
                'limit to reset, then re-run -- retrying immediately will '
                'likely 429 again and hide whatever the real failure was)'
                % (method, path, raw[:300]))
        assert status == expect, '%s %s -> %s %s' % (method, path, status, raw[:300])
        return json.loads(raw) if raw else {}

    def cookie(self, name):
        return next(c.value for c in self.jar if c.name == name)


def origin_for(rp_id):
    return 'http://localhost:1338' if rp_id == 'localhost' else 'https://' + rp_id


def register(client, authenticator, begin_path, finish_path, begin_body):
    begin = client.json('POST', begin_path, begin_body)
    credential = authenticator.register(begin['options'],
                                        origin=origin_for(begin['options']['rp']['id']))
    return client.json('POST', finish_path, {'challenge_id': begin['challenge_id'],
                                             'credential': credential, 'name': 'e2e'},
                       expect=201)


def assertion(client, authenticator):
    begin = client.json('POST', '/api/passkeys/login/begin/', {})
    return {'challenge_id': begin['challenge_id'],
            'credential': authenticator.assert_(begin['options'],
                                                origin=origin_for(begin['options']['rpId']))}


def run(base, username, app, signup_name):
    authenticator = SoftAuthenticator()

    api = Client(base)
    api.token = api.json('POST', '/rest-auth/login/',
                         {'username': username, 'password': PASSWORD})['key']
    api.json('POST', '/api/passkeys/register/begin/', {'password': 'wrong'}, expect=400)
    created = register(api, authenticator, '/api/passkeys/register/begin/',
                       '/api/passkeys/register/finish/', {'password': PASSWORD})
    print('linked passkey after password step-up:', created['name'])

    anon = Client(base)
    key = anon.json('POST', '/api/passkeys/login/finish/', assertion(anon, authenticator))['key']
    assert key == api.token, 'passkey login must return the account token'
    anon.token = key
    assert anon.json('GET', '/rest-auth/user/')['username'] == username
    print('passkey token login: OK')

    web = Client(base)
    query = urllib.parse.urlencode({
        'response_type': 'code', 'client_id': app.client_id, 'redirect_uri': REDIRECT,
        'scope': 'etipitaka:read', 'code_challenge': PKCE_CHALLENGE,
        'code_challenge_method': 'S256', 'state': 'e2e'})
    status, headers, _raw = web.call('GET', '/o/authorize/?' + query)
    assert status == 302, status
    next_url = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['next'][0]
    web.call('GET', '/login/')
    body = dict(assertion(web, authenticator), next=next_url)
    redirect = web.json('POST', '/login/passkey/', body,
                        headers={'X-CSRFToken': web.cookie('csrftoken')})['redirect']
    assert redirect == next_url, redirect
    status, _headers, page = web.call('GET', redirect)
    assert status == 200 and b'name="allow"' in page, status
    print('browser passkey login -> OAuth consent page: OK')

    # `web` is now a signed-in browser session for `username` -- exactly what
    # the desktop handshake's second leg needs. `api.token` is the key
    # /rest-auth/login/ handed out for this same account at the top of run(),
    # and nothing since has revoked it (the password removal that changes the
    # session auth hash happens below, and recovery's revoke_all_tokens later
    # still), so an approved pairing must hand the desktop app that very key.
    desktop_sign_in(base, web, api.token, username)
    desktop_refused(base, web)

    api.json('POST', '/api/passkeys/register/begin/', {'step_up': assertion(anon, authenticator)})
    print('passkey step-up: OK')

    assert api.json('POST', '/api/passkeys/password/remove/',
                    {'password': PASSWORD}) == {'has_password': False}
    only = api.json('GET', '/api/passkeys/')['passkeys'][0]['id']
    api.json('DELETE', '/api/passkeys/%d/' % only, expect=409)
    print('password removed; last passkey guarded: OK')

    newcomer = SoftAuthenticator()
    guest = Client(base)
    register(guest, newcomer, '/api/passkeys/signup/begin/', '/api/passkeys/signup/finish/',
             {'username': signup_name, 'email': signup_name + '@example.com'})
    guest.json('POST', '/api/passkeys/login/finish/', assertion(guest, newcomer), expect=400)
    User.objects.filter(username=signup_name).update(is_active=True)
    assert guest.json('POST', '/api/passkeys/login/finish/', assertion(guest, newcomer))['key']
    print('passkey signup -> verified -> login: OK')

    recover_account(base, username, app, authenticator, api.token)


# --- Task 12 addition: desktop sign-in pairing ------------------------
#
# A wxPython app cannot mint a WebAuthn assertion this server will accept, so
# it borrows the browser's. The protocol, for whoever writes that client:
#
#   1. the app POSTs {} to /api/passkeys/desktop/begin/ and gets back a
#      `device_code` -- the app's SECRET, never displayed, never logged, the
#      only thing that can later collect the token -- plus a `user_code`
#      (XXXX-XXXX), which is the PUBLIC half and is meant to be shown on
#      screen, a `verification_url` to send the human to, and `interval` /
#      `expires_in` saying how often and for how long to poll.
#   2. the human opens that URL in their own, already signed-in browser,
#      checks the code on the page against the one the app is displaying --
#      that comparison is the whole security of this handshake -- and presses
#      Yes or No.
#   3. meanwhile the app POSTs its `device_code` to
#      /api/passkeys/desktop/poll/ every `interval` seconds.
#
# The four poll outcomes, all of which a real client has to tell apart:
#
#   200 {'status': 'pending'}                     keep polling
#   200 {'status': 'approved', 'key', 'username'} signed in; stop polling
#   200 {'status': 'denied'}                      the human said No; stop
#   400 {'detail': ...}                           unknown, expired, or
#       already redeemed -- the server deliberately does NOT distinguish
#       those three (a 400 tells a guesser nothing about whether a code it
#       made up ever existed), so the only sane client reaction is to throw
#       the device code away and start a new pairing.
#
# Note where the line falls: refusal is a 200, not a 400. "The human said no,
# stop" and "this pairing is dead, start over" want opposite behaviour from
# the app, which is why the legs below assert the exact status code and not
# merely that the call failed or succeeded.
#
# Both resolutions are SINGLE-USE. redeem() deletes the row in the same
# transaction that reports approved or denied, so the *next* poll with that
# device code is a 400 -- for a refusal just as much as for an approval. A
# client that keeps polling past a resolution will see that 400 and must not
# read it as "still deciding" or as a fresh, retryable failure.


def desktop_begin(device):
    """Start a pairing as the desktop app would, and check what it is handed.

    `device` is a Client of its own: the app holds no cookies and no session,
    only the device code it gets back here.
    """
    pairing = device.json('POST', '/api/passkeys/desktop/begin/', {}, expect=200)
    user_code, device_code = pairing['user_code'], pairing['device_code']
    # Shown to a human and typed or read aloud, so the shape matters: four
    # characters, a hyphen, four characters.
    assert re.fullmatch(r'[A-Z0-9]{4}-[A-Z0-9]{4}', user_code), user_code
    # The secret must be a secret, not the user code under another name.
    assert device_code != user_code and len(device_code) >= 32, pairing
    assert pairing['verification_url'].endswith('/desktop/?code=' + user_code), pairing
    assert pairing['interval'] == 5, pairing
    assert pairing['expires_in'] == 600, pairing
    return pairing


def desktop_poll(device, pairing, expect=200):
    return device.json('POST', '/api/passkeys/desktop/poll/',
                       {'device_code': pairing['device_code']}, expect=expect)


def desktop_confirm_page(browser, user_code):
    """Open the confirmation page in the signed-in browser session.

    The page must show the same code the app is displaying -- that is what the
    human compares -- and, being @ensure_csrf_cookie, this GET is also what
    mints the CSRF cookie and the hidden field the decision POST needs.
    """
    status, _headers, page = browser.call('GET', '/desktop/?code=' + user_code)
    assert status == 200, (status, page[:300])
    assert user_code.encode() in page, (
        'the confirmation page must show the code the app is displaying: %r' % page[:300])
    assert b'name="csrfmiddlewaretoken"' in page, page[:300]


def desktop_decide(browser, user_code, action):
    """Press Yes ('approve') or No ('deny') and return where it redirects.

    A urlencoded form POST, not JSON: /desktop/approve/ is a plain Django view
    reading request.POST, and it is @csrf_protect, so this carries the
    csrfmiddlewaretoken the GET above just minted -- the same dance
    get_oauth_access_token does for the consent page. The view answers with a
    redirect rather than a rendered page so that refreshing cannot re-submit a
    decision that was already made.
    """
    status, headers, raw = browser.form(
        'POST', '/desktop/approve/',
        {'code': user_code, 'action': action,
         'csrfmiddlewaretoken': browser.cookie('csrftoken')},
        headers={'Referer': browser.base + '/desktop/'})
    assert status == 302, (status, raw[:300])
    return headers['Location']


def desktop_sign_in(base, browser, expected_key, username):
    """The happy path: begin -> pending -> the human approves -> the app's
    next poll collects the account's token, and the one after that is a 400.
    """
    device = Client(base)
    pairing = desktop_begin(device)
    assert desktop_poll(device, pairing) == {'status': 'pending'}, (
        'an undecided pairing must poll as pending and reveal nothing else')
    print('desktop pairing begun; poll before any decision is pending: OK')

    desktop_confirm_page(browser, pairing['user_code'])
    location = desktop_decide(browser, pairing['user_code'], 'approve')
    assert location == '/desktop/?result=approved', location
    print('confirmation page shows the code; Yes approves: OK')

    # Exact dict: status, the token and the account it belongs to. `key` is
    # the same key /rest-auth/login/ returned for this user -- the pairing
    # hands over the existing account token, it does not invent a second one.
    approved = desktop_poll(device, pairing)
    assert approved == {'status': 'approved', 'key': expected_key,
                        'username': username}, approved
    print('poll after approval returns the account token: OK')

    # Single-use: the poll above consumed the row. Indistinguishable from a
    # device code that expired or never existed, all three being a 400.
    desktop_poll(device, pairing, expect=400)
    print('approval is single-use; re-polling the spent code is 400: OK')


def desktop_refused(base, browser):
    """The path the approve leg cannot reach: someone lands on the
    confirmation page without having started a sign-in, and presses No.
    """
    device = Client(base)
    pairing = desktop_begin(device)
    desktop_confirm_page(browser, pairing['user_code'])
    location = desktop_decide(browser, pairing['user_code'], 'deny')
    assert location == '/desktop/?result=denied', location

    # A 200, not the 400 an expired or unknown code gets: the app is being
    # told "the human said no", which is a different instruction from "this
    # code is dead". Asserting the whole dict, and then `key`/`username`
    # again by name, because that is the assertion with teeth here: a server
    # that wrongly minted a token for a refused pairing would still report
    # status 'denied', and only the absence of a key catches it.
    refusal = desktop_poll(device, pairing, expect=200)
    assert refusal == {'status': 'denied'}, refusal
    assert 'key' not in refusal, 'a refused pairing must not mint a token: %r' % refusal
    assert 'username' not in refusal, 'a refused pairing must not name the user: %r' % refusal
    print('No refuses: poll returns 200 denied, with no token: OK')

    # Refusal is consumed by the poll that reports it, exactly like approval.
    desktop_poll(device, pairing, expect=400)
    print('refusal is single-use; re-polling the spent code is 400: OK')


# --- Task 25 addition: account recovery -------------------------------
#
# The plan's own flow above never exercises the recovery path at all
# (several reviews flagged this). It reuses `username`: by this point in
# run() its password was already removed, so it holds exactly one passkey
# (`authenticator`'s) and no other way to sign in -- the scenario recovery
# exists for.


def pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return verifier, challenge


def get_oauth_access_token(client, app):
    """Complete a real OAuth authorization-code + PKCE exchange for the
    already browser-signed-in `client`, returning a fresh access token for
    its account -- the way tests/oauth_e2e.py's get_token() does, but
    in-line here since run()'s own OAuth check above deliberately stops at
    the consent page and never exchanges a code (see its PKCE_CHALLENGE
    comment). A real, revocable access token is exactly what proving
    recovery revokes OAuth credentials needs.
    """
    verifier, challenge = pkce()
    query = urllib.parse.urlencode({
        'response_type': 'code', 'client_id': app.client_id, 'redirect_uri': REDIRECT,
        'scope': 'etipitaka:read', 'code_challenge': challenge,
        'code_challenge_method': 'S256', 'state': 'e2e-recover'})
    status, _headers, page = client.call('GET', '/o/authorize/?' + query)
    assert status == 200 and b'name="allow"' in page, status
    form = {'response_type': 'code', 'client_id': app.client_id, 'redirect_uri': REDIRECT,
            'scope': 'etipitaka:read', 'code_challenge': challenge,
            'code_challenge_method': 'S256', 'state': 'e2e-recover',
            'allow': 'Authorize', 'csrfmiddlewaretoken': client.cookie('csrftoken')}
    status, headers, raw = client.form('POST', '/o/authorize/', form,
                                       headers={'Referer': client.base + '/o/authorize/'})
    assert status == 302, (status, raw[:300])
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['code'][0]
    status, _headers, raw = client.form('POST', '/o/token/', {
        'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT,
        'client_id': app.client_id, 'code_verifier': verifier})
    assert status == 200, (status, raw[:300])
    return json.loads(raw)['access_token']


# Text unique to registration/password_reset_email.txt (this project's own
# template, wired in via password_reset_view's email_template_name) -- the
# stock Django reset email never mentions passkeys at all, so asserting
# this also catches email_template_name silently coming unwired and users
# quietly getting Django's default English "click here to reset your
# password" email with no passkey instructions in it.
_RECOVERY_EMAIL_MARKER = 'พาสคีย์'  # "passkey" (Thai), the default site language


def request_password_reset(email):
    """POST /password_reset/ in-process and return the recovery link's
    path, extracted from the email django's console backend would
    otherwise only print to a different process's stdout. See the module
    docstring's "Email capture" paragraph for why this is in-process while
    everything else in this script -- including a real GET of this same
    /password_reset/ route, in recover_account below -- is real HTTP
    against `base`.

    SERVER_NAME is a fixed, ALLOWED_HOSTS-listed value ('web'): the domain
    it puts in the mailed link is discarded below (only the path is kept,
    for use against the caller's own `base`) -- but the link's
    *absoluteness* (a real scheme://host prefix, not a bare path a mail
    client couldn't turn into a clickable link) is checked before that
    discarding happens.
    """
    with override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
        # locmem's EmailBackend only creates the module-level `outbox` list
        # the first time it actually sends something -- it does not exist
        # yet in a process (like this one) that has never sent mail before.
        before = len(getattr(mail, 'outbox', []))
        status = DjangoTestClient(SERVER_NAME='web').post(
            '/password_reset/', {'email': email}).status_code
        assert status == 302, status
        outbox = getattr(mail, 'outbox', [])
        assert len(outbox) == before + 1, 'expected exactly one recovery email'
        sent = outbox[-1]
        assert sent.to == [email], 'recovery email went to the wrong address: %r' % (sent.to,)
        assert _RECOVERY_EMAIL_MARKER in sent.body, (
            "recovery email doesn't look like this project's own template "
            '(email_template_name unwired back to Django\'s stock one?): %r'
            % sent.body[:300])
        match = re.search(r'https?://[^/\s]+(/reset/[^\s/]+/[^\s/]+/)', sent.body)
        assert match, 'no absolute reset link found in the recovery email: %r' % sent.body[:300]
        return match.group(1)


def recover_passkey(client, authenticator, uidb64):
    csrf = client.cookie('csrftoken')
    begin = client.json('POST', '/account/recover/passkey/begin/', {'uidb64': uidb64},
                        headers={'X-CSRFToken': csrf})
    credential = authenticator.register(begin['options'],
                                        origin=origin_for(begin['options']['rp']['id']))
    return client.json('POST', '/account/recover/passkey/finish/',
                       {'uidb64': uidb64, 'challenge_id': begin['challenge_id'],
                        'credential': credential, 'name': 'e2e-recovered'},
                       headers={'X-CSRFToken': csrf})


def recover_account(base, username, app, lost_authenticator, drf_token):
    # A fresh browser session + OAuth token, minted only now -- strictly
    # after run() already removed the password above. Removing the
    # password changes the session-auth hash and silently signs out any
    # session opened before it (including run()'s own `web` client); a
    # session started only here is unaffected by that, so its later sign-
    # out can be attributed to recovery itself, not to an earlier step.
    recovery_browser = Client(base)
    recovery_browser.call('GET', '/login/')
    redirect = recovery_browser.json(
        'POST', '/login/passkey/', assertion(recovery_browser, lost_authenticator),
        headers={'X-CSRFToken': recovery_browser.cookie('csrftoken')})['redirect']
    assert redirect == '/', redirect
    oauth_token = get_oauth_access_token(recovery_browser, app)
    # `drf_token` is the same token run() minted via password login,
    # already live this whole time (removing the password doesn't touch a
    # DRF token -- only recovery's revoke_all_tokens does): reusing it here
    # rather than minting a fresh one also proves it survived everything
    # else run() already did to this account before recovery even starts.
    live_drf_token = Client(base)
    live_drf_token.token = drf_token
    print('pre-recovery browser session + OAuth token: OK')

    # A real HTTP GET, unlike request_password_reset's in-process POST
    # below: exercises the /password_reset/ route and its form template for
    # real, so the route being removed or renamed in urls.py fails here --
    # request_password_reset's in-process django.test.Client dispatch knows
    # how to reach the view function directly and would not by itself
    # notice the route disappearing from urls.py.
    status, _headers, page = Client(base).call('GET', '/password_reset/')
    assert status == 200 and b'name="email"' in page, (status, page[:300])
    print('GET /password_reset/ shows the reset-request form: OK')

    reset_path = request_password_reset(username + '@example.com')
    recovering = Client(base)
    status, headers, raw = recovering.call('GET', reset_path)
    assert status == 302, (status, raw[:300])
    confirm_path = headers['Location']
    status, _headers, page = recovering.call('GET', confirm_path)
    assert status == 200 and b'id="passkey-recover"' in page, (status, page[:300])
    match = re.search(rb'data-uidb64="([^"]+)"', page)
    assert match, page[:300]
    uidb64 = match.group(1).decode()
    print('recovery link opened -> passkey-recovery form shown: OK')

    fresh_authenticator = SoftAuthenticator()
    result = recover_passkey(recovering, fresh_authenticator, uidb64)
    assert result['redirect'] == '/account/security/', result
    print('account recovery: new passkey created, redirected to /account/security/: OK')

    status, _headers, raw = recovering.call('GET', '/account/security/')
    assert status == 200, (status, raw[:300])
    print('recovering client is signed in: OK')

    # Recovery exists to hand a locked-out user a WORKING credential, not
    # just to run the ceremony and revoke the old ones -- so prove the new
    # passkey can independently sign in through the normal login endpoint
    # (a *different* client than `recovering`, which is already signed in
    # via finish_recover's own login() call and wouldn't notice the new
    # credential itself being unusable, e.g. a corrupted stored public key).
    login_client = Client(base)
    recovered_key = login_client.json(
        'POST', '/api/passkeys/login/finish/', assertion(login_client, fresh_authenticator))['key']
    assert recovered_key, 'the recovered passkey must be able to sign in'
    print('recovered passkey signs in: OK')

    status, _headers, raw = live_drf_token.call('GET', '/rest-auth/user/')
    assert status == 401, (status, raw[:300])
    print('pre-recovery DRF token revoked: OK')

    status, _headers, raw = Client(base).call(
        'GET', '/api/oauth/verify/', headers={'Authorization': 'Bearer ' + oauth_token})
    assert status in (401, 403), (status, raw[:300])
    print('pre-recovery OAuth access token revoked: OK')

    status, headers, _raw = recovery_browser.call('GET', '/account/security/')
    assert status == 302 and '/login/' in headers.get('Location', ''), (status, headers)
    print('browser session opened before recovery is signed out: OK')

    status, _headers, page = Client(base).call('GET', reset_path)
    assert status == 200 and b'label-danger' in page, (status, page[:300])
    print('reset link is spent (re-opening it shows the invalid-link page): OK')


def main(base):
    suffix = secrets.token_hex(4)
    username, signup_name = 'e2e_pk_' + suffix, 'e2e_su_' + suffix
    # Application first, and outside the try: the finally block's app.delete()
    # needs it to exist unconditionally, including if User creation itself
    # (inside the try below) is what fails.
    app = Application.objects.create(
        name='passkey-e2e', client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris=REDIRECT, client_secret='', hash_client_secret=False)
    try:
        User.objects.create_user(username, username + '@example.com', PASSWORD)
        run(base, username, app, signup_name)
    finally:
        for name in (username, signup_name):
            user = User.objects.filter(username=name).first()
            if user is not None:
                # Sessions carry no FK to User (django.contrib.sessions is
                # decoupled from auth), so deleting the user below would
                # not on its own clean up recover_account's leftover
                # recovering-client session row. Best-effort: a failure
                # here (e.g. a transient DB error) must not skip deleting
                # the user/app rows below, which matter more -- a stray
                # session row is comparatively harmless (it expires on its
                # own; see delete_user_sessions's own docstring).
                with contextlib.suppress(Exception):
                    delete_user_sessions(user)
        User.objects.filter(username__in=[username, signup_name]).delete()
        app.delete()
    print('PASSKEY E2E OK')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'http://web:8000')
