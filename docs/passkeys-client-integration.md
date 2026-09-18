# Passkeys — client integration and operator guide

Server side of passkey sign-in for E-Tipitaka. Design:
`docs/superpowers/specs/2026-09-14-passkey-login-design.md`. Reverse-proxy
and rate-limit details referenced below are covered in full in
`docs/remote-mcp-oauth-deploy.md`.

- **Relying party ID:** `data.etipitaka.com`
- **Web origin:** `https://data.etipitaka.com`
- **Discoverable credentials, user verification required, attestation `none`.**

## Ceremony shape

Every ceremony is two POSTs with JSON bodies.

1. **begin** → `200 {"challenge_id": "...", "options": {...}}`. `options` is
   the standard `PublicKeyCredentialCreationOptionsJSON` or
   `PublicKeyCredentialRequestOptionsJSON`.
2. **finish** ← `{"challenge_id": "...", "credential": {...}}`. `credential`
   is the standard `RegistrationResponseJSON` / `AuthenticationResponseJSON`
   (base64url fields, `response.transports` on registration,
   `response.userHandle` on login).

A challenge is single use (the row is deleted before the response is even
verified, so a failed attempt burns it too), expires after 5 minutes
(`PASSKEY_CHALLENGE_TTL`), and only finishes the ceremony purpose and user it
was issued for. A reused, expired or wrong-ceremony challenge returns 400;
start again with begin.

## Malformed request bodies

Every `/api/passkeys/*` endpoint is a thin DRF view that always touches
`request.data` before reading a field, even when it has none to read (e.g.
`login/begin`). A body that parses as JSON but isn't an object (a list,
string or number), or one nested so deeply it exhausts the parser, comes
back as `400 {"detail": "Malformed request."}`; a body that isn't valid JSON
at all gets DRF's own generic parse-error 400 instead. This is a global
safety net (`user_data/drf_handlers.py`, wired in as DRF's
`EXCEPTION_HANDLER`) — a crafted request can only ever reach a 400 here,
never a 500.

`/login/passkey/` and the two `/account/recover/passkey/*` endpoints are
**not** DRF views (see below), so they don't produce that message: an
unparseable or wrong-shaped body is silently treated as `{}` and falls
through to that endpoint's own error — e.g. recovery reports "This password
reset link is invalid or has expired." rather than "Malformed request."

## Endpoints

Authentication column: **none** = anonymous, no cookie or token needed;
**anon, CSRF** = anonymous but requires an `X-CSRFToken` matching a CSRF
cookie (`/login/passkey/`) or, for the two recovery endpoints, also a valid
reset-link session already established by opening the emailed link
(`INTERNAL_RESET_SESSION_TOKEN`) — native clients never call any of these
three rows directly, only the web pages do; **account** = signed-in caller,
via `Authorization: Token <key>` (apps) or the web session + `X-CSRFToken`;
**session** = signed-in caller via the web session cookie *only* — a plain
Django view behind `@login_required`, where `Authorization: Token` is not
honoured at all — plus CSRF on the POST. The two `/desktop/` rows are the
only ones of that kind: a desktop client opens them in the system browser and
never calls them itself (see "Desktop (browser-delegated)").
OAuth bearer tokens are **rejected** on every account endpoint, so a
read-scoped MCP connector token can never manage passkeys.

| Endpoint | Auth | Body | Success | Errors |
|---|---|---|---|---|
| `POST /api/passkeys/login/begin/` | none | `{}` | 200 ceremony | 400 malformed body; 429 |
| `POST /api/passkeys/login/finish/` | none | ceremony | 200 `{"key": "<token>"}` (same shape as `/rest-auth/login/`) | 400 `{"non_field_errors": [msg]}` — bad credentials, or "account not active" (see below); 400 malformed body; 429 |
| `POST /login/passkey/` | anon, CSRF | `{challenge_id, credential, next}` | 200 `{"redirect": <safe target>}` + session cookie (`Cache-Control: no-store`) | 400 `{"detail": msg}` — same two messages as above; 403 CSRF failure; 429 (nginx only — this is a plain Django view, so the DRF `passkey` throttle never runs here) |
| `POST /api/passkeys/desktop/begin/` | none | `{}` | 200 `{"device_code", "user_code", "verification_url", "interval", "expires_in"}` | 400 malformed body; 429 |
| `POST /api/passkeys/desktop/poll/` | none | `{"device_code"}` | 200 `{"status": "pending"}`, `{"status": "approved", "key", "username"}` or `{"status": "denied"}` | 400 `{"detail": "This sign-in request has expired…"}` — unknown, expired *or* already redeemed, and a missing/non-string `device_code` too; 400 malformed body; 429 |
| `GET /desktop/?code=<user_code>` | session | — | 200 confirmation page (`Cache-Control: no-store`) | 302 → `/login/?next=…` when signed out; 429 (nginx only, and an HTML page) |
| `POST /desktop/approve/` | session, CSRF | form-encoded `code`, `action`, `csrfmiddlewaretoken` | 302 → `/desktop/?result=approved\|denied\|stale` (`Cache-Control: no-store`) | 403 CSRF failure; 429 (nginx only, HTML) |
| `POST /api/passkeys/signup/begin/` | none | `{"username", "email"}` | 200 ceremony | 400 field errors; 400 malformed body; 429 |
| `POST /api/passkeys/signup/finish/` | none | ceremony + optional `"name"` | 201 `{"detail": "Verification e-mail sent."}` — account inactive until the emailed link is opened | 400 field errors (taken since begin); 400 `{"detail": "Passkey registration failed."}`; 400 malformed body; 429 |
| `POST /api/passkeys/register/begin/` | account | `{"password"}` **or** `{"step_up": {"challenge_id", "credential"}}` | 200 ceremony | 400 `{"detail": "Re-authentication failed."}`; 409 `{"detail": "You have reached the maximum number of passkeys."}` (cap of 20, see below); 400 malformed body; 401; 429 |
| `POST /api/passkeys/register/finish/` | account | ceremony + optional `"name"` | 201 passkey object | 400 `{"detail": "Passkey registration failed."}`; 409 max-passkeys (same as above); 400 malformed body; 401; 429 |
| `GET /api/passkeys/` | account | — | 200 `{"has_password", "passkeys": [passkey…]}` | 401; 429 (a body, if sent at all, must still be a JSON object or 400) |
| `PATCH /api/passkeys/<id>/` | account | `{"name"}` | 200 passkey object | 400 `{"name": [...]}` empty name; 404 not owned; 400 malformed body; 401; 429 |
| `DELETE /api/passkeys/<id>/` | account | — | 204 | 404 not owned; 409 `{"detail": "Your account must keep at least one way to sign in."}` (last passkey, no password); 400 malformed body (if a body is sent); 401; 429 |
| `POST /api/passkeys/password/remove/` | account | `{"password"}` | 200 `{"has_password": false}` | 400 `{"detail": "Re-authentication failed."}` (wrong password); 409 `{"detail": "Your account must keep at least one way to sign in."}` (no passkey exists yet); 400 malformed body; 401; 429 |
| `POST /account/recover/passkey/begin/` | anon, CSRF, reset-link session | `{"uidb64"}` | 200 ceremony (`Cache-Control: no-store`) | 400 `{"detail": "This password reset link is invalid or has expired."}`; 429 |
| `POST /account/recover/passkey/finish/` | anon, CSRF, reset-link session | `{"uidb64", "challenge_id", "credential", "name"?}` | 200 `{"redirect": "/account/security/"}` + session cookie (`Cache-Control: no-store`) | 400 same invalid-link message; 400 `{"detail": "Passkey registration failed."}`; 429 |
| `GET/HEAD /.well-known/apple-app-site-association` | none | — | 200 `application/json` | 404 JSON when `PASSKEY_IOS_APP_IDS` is empty; 405 other methods; never rate-limited |
| `GET/HEAD /.well-known/assetlinks.json` | none | — | 200 `application/json` | 404 JSON when `PASSKEY_ANDROID_PACKAGE` or `PASSKEY_ANDROID_CERT_SHA256` is empty; 405 other methods; never rate-limited |

Passkey object: `{"id", "name", "authenticator", "backed_up", "created_at", "last_used_at"}`.

**Every error string comes back in Thai, and `Accept-Language` will not
change that.** `LANGUAGE_CODE = 'th'`, and the project's own
`etipitaka_auth.i18n.LanguageMiddleware` picks the active language from the
`django_language` cookie alone — it does no `Accept-Language` negotiation,
deliberately (there is no `django.middleware.locale.LocaleMiddleware` in
`MIDDLEWARE`). A native client sends no cookies, so it gets the site default
on every request. Verified against the running stack: `Accept-Language: en`
on `/api/passkeys/desktop/poll/` still answers
`{"detail": "คำขอเข้าสู่ระบบนี้หมดอายุแล้ว กรุณาลองใหม่"}`, and
`/api/passkeys/login/finish/` answers
`{"non_field_errors": ["ไม่สามารถเข้าสู่ระบบด้วยข้อมูลที่ให้มาได้"]}` — this is
site-wide, not something these endpoints do on their own. Two ways out, in
order of preference:

- **Branch on the status code plus the machine-readable field** (`status` on
  desktop poll, the presence of `key`, the HTTP code elsewhere) and render
  your own strings. `detail` is a generic fallback, not an API contract.
- **Send `Cookie: django_language=en`** on API calls if you would rather let
  the server phrase it. The only values `settings.LANGUAGES` recognises are
  `th` and `en`, anything else falls back to Thai, and there is no `en`
  catalogue — so "English" is simply the msgid, the English source string
  (`{"detail": "This sign-in request has expired. Please try again."}`).

A client that just displays `detail` verbatim shows Thai to every user
whatever the app's own UI language is set to.

**Passkey cap:** an account may hold at most 20 passkeys (`PASSKEY_MAX_PER_USER`
in `user_data/passkey_service.py`). The cap applies to `register/begin` and
`register/finish` only — never to signup (the account's first passkey) or to
recovery, so a full account can never be locked out of its own recovery flow.

**"Account not active" on login:** the message exists on both the password
and passkey login paths, but is only *reachable* on the passkey one.
`finish_login` verifies the assertion first and then explicitly checks
`user.is_active`, so an unverified passkey-signup account gets the specific
message. On the password path, Django's `ModelBackend.authenticate()`
already returns `None` for an inactive user before `LoginSerializer` ever
gets to check `is_active` itself, so a password login against an unverified
account always gets the generic "Unable to log in with provided
credentials." instead — same string in the code, different reachability.

**Removing a password does not revoke tokens.** A device's DRF token keeps
working after the account owner drops their password fallback
(`/api/passkeys/password/remove/`) — that is by design. Only account
recovery (below) revokes tokens. Removing a password *does*, however, sign
out every **other** browser session: `set_unusable_password()` still
rewrites the stored password hash (to an unusable value), which
invalidates Django's session-auth-hash check for any session already
holding the old one; `update_session_auth_hash(request, user)` rescues
only the browser session that made this exact request, not any other one
signed in as the same user.

**Security notification emails.** Three actions each send a best-effort
email to the account's address, so an owner is never surprised by a change
they didn't make: adding a passkey (`register/finish`, `signup/finish` and
passkey recovery), deleting a passkey (`DELETE /api/passkeys/<id>/`), and
removing the password (`/api/passkeys/password/remove/`). All three share
one render/send/swallow-and-log helper
(`passkey_service._send_security_email`); a mail outage is logged, never
surfaced to the caller as a failed request, and never rolls back the
change it's reporting — each email is
sent strictly after its own transaction has committed. This closes the gap
where only "passkey added" used to notify the owner: a stolen session that
added its own passkey, dropped the password, and deleted the real owner's
passkeys used to do all of that silently after the first email.

## Flows

**Sign in:** `login/begin` → system passkey sheet → `login/finish` → store the
token exactly as after password login.

**Sign in from a desktop app:** `desktop/begin {}` → show the `user_code` and
open `verification_url` in the system browser → poll `desktop/poll
{"device_code"}` every `interval` seconds until it answers something other
than `pending`. No ceremony happens in the app at all. Full contract, including
the four poll outcomes, in "Desktop (browser-delegated)" below.

**Link a passkey (existing users):** ask for the current password →
`register/begin {"password"}` → system sheet → `register/finish`. A user with
no password proves themselves with a passkey first: `login/begin` → sheet →
send `{"step_up": {challenge_id, credential}}` to `register/begin`. The account
owner receives a "new passkey added" email (see "Security notification
emails" above). A 21st passkey is rejected with 409 before the sheet ever
opens.

**Sign up:** `signup/begin {"username", "email"}` → sheet → `signup/finish` →
tell the user to open the verification email. Until then `login/finish`
returns 400 "This account is not active…". Username and email rules
(`AccountIdentitySerializer`, shared with password signup) apply: username
≤150 characters, email ≤254 characters, and both are matched
**case-insensitively** (username is also NFKC-normalised before the check
and before it's stored, so visually-identical fullwidth spellings collide
with the plain one) — see "Known gaps" below for the production-rollout
caveat.

**Lost passkey / forgot password:** open `https://data.etipitaka.com/password_reset/`
in `ASWebAuthenticationSession` (iOS) or a Custom Tab (Android). The emailed
link lets the user create a new passkey (saved under the same RP ID, so the
app can use it immediately) or set a password. Recovery revokes every DRF and
OAuth token the account holds and **also signs out every other browser
session** for that account (the browser doing the recovering keeps its own,
freshly-cycled session) — so a lost device's app token stops working and it
must sign in again, and any other browser tab signed in as that user is
signed out too, on either recovery path (new passkey or new password).

## iOS

- Entitlement **Associated Domains**: `webcredentials:data.etipitaka.com`.
- The server publishes `https://data.etipitaka.com/.well-known/apple-app-site-association`
  listing `A6DJDJ7527.com.watnapp.E-Tipitaka-Plus` (or whatever
  `PASSKEY_IOS_APP_IDS` is set to — an empty list serves a 404 instead, which
  breaks passkey association entirely, so don't clear that variable without
  replacing it). Apple fetches it through its CDN; after a deploy check
  `https://app-site-association.cdn-apple.com/a/v1/data.etipitaka.com`.
- Use `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "data.etipitaka.com")`:
  `createCredentialRegistrationRequest(challenge:name:userID:)` with the
  decoded `options.challenge` / `options.user.id`, and
  `createCredentialAssertionRequest(challenge:)` for login. Set
  `userVerificationPreference = .required`. For login autofill use
  `performAutoFillAssistedRequests()`.
- Build `credential` JSON from `ASAuthorizationPlatformPublicKeyCredentialRegistration`
  (`rawClientDataJSON`, `rawAttestationObject`, `credentialID`) and
  `…Assertion` (`rawClientDataJSON`, `rawAuthenticatorData`, `signature`,
  `userID`, `credentialID`), base64url-encoding each field. iOS reports origin
  `https://data.etipitaka.com`.

## Android

- The operator sets `PASSKEY_ANDROID_PACKAGE` and `PASSKEY_ANDROID_CERT_SHA256`
  (see below); until then `/.well-known/assetlinks.json` is 404 and Android
  assertions are rejected (no Android origin is ever accepted into the list
  `passkey_config.expected_origins()` returns).
- Use Credential Manager: `CreatePublicKeyCredentialRequest(requestJson)` and
  `GetPublicKeyCredentialOption(requestJson)`, passing `options` as JSON. The
  returned `registrationResponseJson` / `authenticationResponseJson` is sent as
  `credential` unchanged.
- Android reports origin `android:apk-key-hash:<base64url(SHA-256 of signing cert)>`;
  the server derives it from `PASSKEY_ANDROID_CERT_SHA256`.

## Desktop (browser-delegated)

**A desktop client never posts credential JSON at all.** A WebAuthn ceremony
is bound to an origin; the origin is asserted by the browser or the OS, never
by the page or the app; and `passkey_config.expected_origins()` accepts
exactly one for the web, `https://data.etipitaka.com`. iOS and Android get
origins of their own into that list through the two association files above.
A wxPython process has no equivalent — there is nothing it could claim that
the server would accept — so it cannot call `login/finish` or
`register/finish` however it obtains a credential. Instead the ceremony
happens where it already works, in the user's own browser on the registered
origin, and the app collects only the *result* through a device-pairing
hand-off: the app is issued a code, the human approves that code in their
signed-in browser, and the app polls until it is handed the account's token.

The shape is the OAuth device grant's, but the implementation is this
project's own (`user_data/desktop_pairing.py`) — `etipitaka_auth/urls.py`
deliberately does **not** mount django-oauth-toolkit's device-code grant, so
`/o/device/...` does not exist and is not the thing to build against.

**begin.** `POST /api/passkeys/desktop/begin/`, anonymous — nobody is signed
in yet, and the handshake is worthless without the browser leg. The body must
still be a JSON object (`{}`); the view touches `request.data` like every
other, so anything else is a malformed-body 400.

```
POST /api/passkeys/desktop/begin/
{}

200 {"device_code": "xY3kQd7ZmT2vR9pL4wN8bH5cJ1sF6gK0aE-tU_nV2Qw",
     "user_code": "6RX5-PDCK",
     "verification_url": "https://data.etipitaka.com/desktop/?code=6RX5-PDCK",
     "interval": 5,
     "expires_in": 600}
```

- `device_code` — the app's **secret** (`secrets.token_urlsafe(32)`, 43
  URL-safe characters). Only its SHA-256 reaches the database, so the server
  can never show it to anyone; neither should the app. Never display it,
  never log it, never put it in a window title or a crash report. It is the
  one thing that can collect the token.
- `user_code` — the **public** half, always `XXXX-XXXX`: eight characters
  drawn from `CODE_ALPHABET`, `23456789ABCDEFGHJKMNPQRSTVWXYZ`, hyphenated in
  the middle for reading. That is Crockford-style — no `0`, `1`, `I`, `L`,
  `O` or `U` — because this code gets read off one screen and compared with
  another, or read down a phone line, and `0`/`O` and `1`/`I`/`L` are where
  that goes wrong. Show it exactly as returned. A client does not need to
  accept typed codes at all (`verification_url` already carries it), but if
  it does: the server's `normalise_user_code` strips every non-alphanumeric
  and upper-cases, so hyphens, spaces, non-breaking spaces, tabs and
  autocorrected en/em dashes all survive a trip through a chat app — it does
  **not** fold `O` to `0` or `I` to `1`, so a genuinely mistyped character is
  rejected rather than guessed at. Don't fold it client-side either.
- `verification_url` — `<web origin>/desktop/?code=<user_code>`. Open it in
  the **system** browser (`webbrowser.open`), not an in-app WebView the app
  controls: the entire security of this handshake is a human comparing the
  code on that page with the code in the app, in a browser the app cannot
  drive. Take the URL as given rather than rebuilding it from a hardcoded
  host — it is composed from the server's configured `PASSKEY_WEB_ORIGIN`.
- `interval` — seconds between polls, currently 5 (`DESKTOP_POLL_INTERVAL`).
  Read it from the response; don't hardcode 5.
- `expires_in` — seconds the pairing stays alive, currently 600
  (`PASSKEY_DESKTOP_TTL`). Ten minutes, not the challenge TTL's five, because
  the window has to cover opening a browser, signing in to the website if
  there is no session yet, and only then confirming. Past it, poll is a 400
  and the app must begin again.

**poll — four outcomes, and a client has to tell all four apart.**
`POST /api/passkeys/desktop/poll/` with `{"device_code": "<the secret>"}`,
anonymous, no faster than `interval`:

| Response | Meaning | What the client does |
|---|---|---|
| 200 `{"status": "pending"}` | the human has not decided | wait `interval`, poll again |
| 200 `{"status": "approved", "key": "<token>", "username": "<name>"}` | approved | stop polling; store `key` exactly as after `/rest-auth/login/` |
| 200 `{"status": "denied"}` | the human pressed **No** | stop polling, say the request was refused. No `key`, no `username` — and don't silently start a new pairing on their behalf |
| 400 `{"detail": …}` | unknown, expired, or already redeemed | throw the device code away and begin again |

Note where the line falls: **refusal is a 200, not a 400.** "The human said
no, stop" and "this pairing is dead, start over" want opposite behaviour from
the app, and a client that only checks `response.ok` will get one of them
wrong. Branch on the status code first, then on `status`.

The 400 is deliberately one undifferentiated case: `redeem()` raises the same
`PairingError` for a code that never existed, one that expired and one that
was already redeemed, so a guesser learns nothing about whether a code it
invented was ever real. A missing or non-string `device_code` lands there
too. (A body that is not a JSON object at all is the generic
`{"detail": "Malformed request."}` 400 instead — see "Malformed request
bodies".)

**Both resolutions are single-use.** `redeem()` deletes the row inside the
same transaction that reports `approved` *or* `denied` — a refusal is
consumed exactly like an approval — so the very next poll with that device
code is a 400. A client that keeps polling past a resolution must not read
that 400 as "still deciding", nor as a fresh failure worth retrying. The row
is selected `FOR UPDATE` and deleted in the transaction that mints the token,
so two concurrent polls can never both be served.

**The approved token is delivered at most once, not at least once.** A crash
*inside* that transaction rolls back and leaves the pairing intact to retry.
But once it commits, the row is gone — so if the process dies, the connection
drops, or a proxy times out after COMMIT and before the client has read the
body, the token is lost to the app: the next poll gets the undifferentiated
400 and the human has to walk the browser leg again. A client should treat a
400 immediately following a poll that never returned a body as "start over",
not as a transient error to retry.

Approval hands over the account's **existing** DRF token
(`Token.objects.get_or_create`) — the same `key` `/rest-auth/login/` or
`login/finish` would return for that user, not a second one minted for this
device. Revoking it (account recovery does) logs every holder out at once.

**A 429 is not a pairing failure.** nginx rejects the request before it
reaches Django, so the pairing is untouched: still pending, still valid until
`expires_in`. Back off for `Retry-After` and resume polling the same
`device_code`. Tearing the handshake down and making the user read a fresh
code off the screen is the wrong reaction to it, and throws away a pairing
that was fine. The `Retry-After` on this surface is **5**, chosen to match
`interval` rather than the zone's actual refill time, precisely so that a
client honouring it cannot end up polling *faster* under load than it does
normally — see "Rate limits". The flip side: do not poll faster than
`interval`. A steady poll is about 12 req/min and nowhere near either
limiter; it is a burst that trips one — measured, a hot loop takes its first
429 from nginx at around the 64th request.

**`detail` is Thai.** See "Every error string comes back in Thai" under
Endpoints — it is site-wide, not specific to these two endpoints, and a
desktop app with its own translation catalogue should branch on status code
plus `status` rather than display it.

**The browser leg, for reference.** The app never calls these two, but they
are what the human walks through and what any support conversation will be
about. `GET /desktop/?code=<user_code>` is `@login_required`, so a user with
no session is bounced to `/login/?next=/desktop/%3Fcode%3D…` and signs in
there — with a passkey, if they have one — before the page appears. The page
names the signed-in account, shows the code, and offers **Yes, allow** /
**No**; the decision is a CSRF-protected form POST to `/desktop/approve/`,
which redirects to `/desktop/?result=approved|denied|stale` so that
refreshing cannot re-submit a decision already made. Anything other than
`action=approve` denies, so a mangled form fails safe. `result=stale` means
the pairing was no longer pending when the decision arrived (decided in
another tab, consumed by a concurrent poll, or expired) — it says only that
*this* button press changed nothing; the app's own poll remains the authority
on what happened. A code that is unknown, expired or already decided renders
the "this sign-in request has expired" page rather than an error.

**Three browser URLs a desktop client should open**, all in the system
browser — none of them has a native equivalent, and a desktop app has no
business rendering any of them itself:

| Purpose | URL |
|---|---|
| Create an account | `https://data.etipitaka.com/signup/` |
| Add, rename or delete passkeys; drop the password fallback | `https://data.etipitaka.com/account/security/` |
| Lost passkey / forgot password | `https://data.etipitaka.com/password_reset/` |

The middle one is `@login_required` too, so an app sending a user there when
their browser has no session lands them on `/login/` first. And recovery
revokes every DRF and OAuth token the account holds (see "Flows"), so a
desktop app holding a token will start getting 401s once the user recovers,
and has to run the pairing handshake again.

**Worked example.** Adapted from `desktop_sign_in`/`desktop_refused` in
`tests/passkey_e2e.py`, which is a working client for exactly this flow;
`show_code`, `refused`, `restart`, `signed_in` and `expired` are the app's
own.

```python
import time, webbrowser, requests

BASE = 'https://data.etipitaka.com'


def sign_in():
    p = requests.post(BASE + '/api/passkeys/desktop/begin/', json={}).json()
    show_code(p['user_code'])               # "6RX5-PDCK", displayed exactly as given
    webbrowser.open(p['verification_url'])  # system browser, never an in-app view

    deadline = time.monotonic() + p['expires_in']
    while time.monotonic() < deadline:
        time.sleep(p['interval'])           # never poll faster than this
        r = requests.post(BASE + '/api/passkeys/desktop/poll/',
                          json={'device_code': p['device_code']})
        if r.status_code == 429:            # pairing untouched and still alive
            time.sleep(int(r.headers.get('Retry-After', p['interval'])))
            continue
        if r.status_code == 400:            # unknown, expired or already redeemed
            return restart()
        state = r.json()
        if state['status'] == 'pending':
            continue
        if state['status'] == 'denied':     # the human said No -- do not retry
            return refused()
        return signed_in(state['key'], state['username'])
    return expired()                        # expires_in elapsed, no decision
```

## Rate limits

Two independent layers; a client hitting either gets a 429. **Honour
`Retry-After` on every 429** — do not just retry immediately.

**nginx** (`nginx/nginx.conf`; full rationale and numbers in
`docs/remote-mcp-oauth-deploy.md`), keyed on client IP (recovered from
`X-Forwarded-For` via `set_real_ip_from`/`real_ip_recursive`), body capped at
64 KiB on every location below:

- Anonymous ceremonies and browser passkey login/recovery —
  `/api/passkeys/(login|signup)/*`, `/login/passkey/`,
  `/account/recover/passkey/*` — **60 req/min, burst 30**.
- Desktop pairing — `/api/passkeys/desktop/*` — **120 req/min, burst 60**, in
  a zone of its own (`passkey_desktop_rl`), listed ahead of the general
  `/api/passkeys/` location so the more specific regex wins. Sized for
  sustained polling rather than the ceremonies' two-shot bursts.
- Signed-in passkey management — the rest of `/api/passkeys/*` (list,
  rename, delete, register, remove password) **and the two `/desktop/`
  confirmation pages** — **60 req/min, burst 20**. The desktop pages share
  this zone rather than the anonymous one because both views are
  `@login_required`: `limit_req` state lives in the zone, so putting them on
  the ceremony zone would let one IP's login/signup flood drain the bucket a
  *different* person behind that NAT needs in order to press **Yes**.
- `/password_reset/` and the `/reset/<uidb64>/...` confirm pages (reached
  when a client opens the recovery link in an in-app browser, not through
  the JSON API): **GET 20 req/min burst 10**, **POST 5 req/min burst 3** —
  method-aware, since a normal recovery is already GET → GET → POST.

A throttled nginx request on any passkey/recovery location gets
`429 {"error":"rate_limited","retry_after":1,"detail":"Too many requests. Please wait a moment and try again."}`
(the `detail` key is additive over `error`/`retry_after`, for a client that
just displays that field generically), with the `Retry-After` header carrying
the same number. Two departures from that:

- `/api/passkeys/desktop/*` reports **`retry_after: 5`**, not the 0.5 s its
  zone actually refills in. 5 is the `interval` the begin response already
  handed the client: a client that honours `retry_after` — the obvious
  reading, and what `assets/passkey.js` already does — would read a 1 there
  as licence to come back five times *faster* than the cadence the same API
  just asked it to keep, i.e. to speed up under load.
- `/password_reset/`/`/reset/.../` **and `/desktop/`, `/desktop/approve/`**
  answer with a small HTML page instead of JSON. Both surfaces are a browser
  navigating — an emailed link, a form POST and its post-redirect GET — not a
  script calling `fetch`, and someone one button away from finishing must not
  be handed a raw JSON blob as the page. The desktop one says so explicitly:
  wait, reload, and the code on your computer is still valid.

**DRF**, layered underneath (`REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['passkey']`,
currently **20/min**): per authenticated user on account endpoints, per
client IP otherwise. This throttle is per gunicorn worker (no shared cache
across workers — see the design doc's Component 1), so it is a second,
looser-in-practice safety net behind nginx's zone, not the primary control;
`NUM_PROXIES: 1` is set so it keys on the real client IP (the last entry of
`X-Forwarded-For`) rather than letting a client spoof a fresh IP on every
request.

The desktop pairing endpoints use a separate DRF scope, `passkey_desktop`, at
**90/min**, keyed on client IP (their callers are anonymous) — its own bucket,
so a second machine behind the same NAT cannot starve the first.

**In practice nginx is the limit that binds on this surface, not DRF.** The
zone was sized on the opposite intent — 2 r/s above DRF's 1.5 r/s, so that a
steady poll would be shaped by DRF with nginx as the coarse backstop — but the
per-worker caveat in the paragraph above defeats that: with three gunicorn
workers and no shared cache, the 90/min is really ~90/min *per worker*, up to
~270/min in aggregate, above nginx's 120. Shapes compound it: nginx is a leaky
bucket while `UserRateThrottle` is a sliding window that passes all 90 in the
first second, so a burst trips nginx first regardless (measured: first 429 at
about request 64, DRF never firing). Treat the DRF scope as defence in depth.
A client should size its behaviour against **120/min sustained, burst 60**.

If DRF *does* fire — it can, on a single worker within one window — the body
is **not** the nginx shape documented above. It is DRF's own
`{"detail": "Request was throttled. Expected available in N seconds."}`: no
`error` key, no `retry_after` key, and a `Retry-After` header computed from the
remaining sliding window, up to ~60. A client that branches on the JSON
`retry_after` field will `KeyError` on this path, so read the `Retry-After`
header and treat a missing `retry_after` body key as "back off by the header".
The divergence is in the safe direction (it backs off harder), but the two
shapes are genuinely different and both are reachable.

## Testing native clients

Native passkeys need the association files over real HTTPS; `localhost` does
not work. Test against production, or expose a dev stack through an HTTPS
tunnel and set `PASSKEY_RP_ID` / `PASSKEY_WEB_ORIGIN` to the tunnel host.

Internal engineers: `tests/passkey_e2e.py` exercises the whole server-side
flow (password login → step-up → register → passkey login → desktop pairing,
both approved and refused → recovery → lockout guards) against a running
stack, and `tests/passkey_js_test.mjs`
unit-tests `app/assets/passkey*.js` and `account_security.js` on the host
(Node, not the container — see `tests/README.md` for exact commands).

## Operator settings

Set in each environment's **gitignored** `docker-compose.override.yml`
(`services.web.environment`), never the tracked `.env`:

| Variable | Default | Example |
|---|---|---|
| `PASSKEY_RP_ID` | host of `OAUTH_ISSUER_URL` | dev: `localhost` |
| `PASSKEY_WEB_ORIGIN` | `OAUTH_ISSUER_URL` | dev: `http://localhost:1338` |
| `PASSKEY_IOS_APP_IDS` | `A6DJDJ7527.com.watnapp.E-Tipitaka-Plus` | comma list; empty → AASA 404s |
| `PASSKEY_ANDROID_PACKAGE` | empty | `com.watnapp.etipitaka` |
| `PASSKEY_ANDROID_CERT_SHA256` | empty | `AB:CD:…` (comma list, colon-hex) |

Passkeys are bound to the RP ID: passkeys created against `localhost` never
work on production. Remove the dev override before running the golden harness.

`PASSKEY_RP_ID` and `PASSKEY_WEB_ORIGIN` are stripped of surrounding
whitespace, so a stray space in a compose file's value cannot silently
produce a broken relying party. `PASSKEY_ANDROID_PACKAGE` and
`PASSKEY_ANDROID_CERT_SHA256` are validated at boot by a Django system
check (`user_data/checks.py`): each fingerprint must decode to a 32-byte
SHA-256 hash, and the two settings must be either both set or both left
empty. `docker compose exec web python manage.py check` (part of the
deploy check gate) fails with a clear message on a bad value instead of it
surfacing later as a 500 at login or a silently 404'd `assetlinks.json`.

`TRUST_PROXY_PROTO=1`, set the same way, is not a passkey-specific setting,
but changes passkey behaviour directly: once it is on, it also marks the
session and CSRF cookies `Secure` (HTTPS-only), on top of trusting
`X-Forwarded-Proto`. That means `/login/passkey/`, `/account/recover/passkey/*`
and `/account/security/` all stop setting a cookie the browser will actually
send back over plain HTTP the moment it's enabled — the request still
succeeds, the session/CSRF cookie is just silently never returned. Only
enable it once the host-level TLS proxy in front of this stack is confirmed
to always overwrite `X-Forwarded-Proto` (never pass through a client-supplied
value); see `docs/remote-mcp-oauth-deploy.md` for the full contract.

## Known gaps

Left open deliberately by design review, so the next reader isn't surprised:

- **No shared cache, so every DRF throttle is per gunicorn worker.**
  `settings.py` configures no `CACHES`, so Django uses per-process
  `LocMemCache` and `docker-compose.yml` runs `--workers 3`. Every
  `DEFAULT_THROTTLE_RATES` figure in this document is therefore a
  *per-worker* figure: the real aggregate ceiling is roughly three times the
  number quoted. `LocMemCache` also culls at `MAX_ENTRIES = 300`, so beyond a
  few hundred distinct client IPs throttle history is discarded at random
  mid-window. nginx's zones are unaffected (its state is shared) and are the
  limits that actually bind. Configuring a shared cache backend would make the
  DRF layer behave as its numbers claim; until then, do not rely on a DRF rate
  as a security control.
- **Desktop pairing is phishable, and the prefilled code is why.** The
  confirmation code is the whole defence: an attacker who starts their own
  pairing sees a different code from the one on the victim's screen. But the
  `verification_url` prefills the code (RFC 8628's `verification_uri_complete`),
  so a phishing link prefills the *attacker's* code too and the user cannot
  catch it by comparison alone. Accepted in the design review in exchange for
  not making every user type eight characters, and mitigated by the explicit
  "did *you* start this?" framing and by naming the signed-in account on the
  page. Forcing manual entry is the stricter alternative and remains a one-line
  change if abuse appears. A desktop client must therefore open the URL itself
  and never instruct users to follow a pairing link from anywhere else.
- **The confirmation page cannot say which computer is asking.** A pairing
  carries no device name or app identifier, so the human's only evidence is the
  code and the fact that they just pressed something. Client screen copy should
  show the code prominently and next to the app's own name, since the page
  cannot corroborate either.
- **There is no cancel endpoint.** An app that abandons a pairing simply stops
  polling and the row dies at `expires_in` (600s). Expired rows are purged
  opportunistically inside `begin()`; there is no sweeper, so an idle period
  leaves expired rows in the table until the next pairing starts.
- **Signup can squat email/username variants**, and a never-activated
  account is never purged automatically; there is no resend-verification
  endpoint (same as the existing password signup).
- **Case-insensitive identity matching has no DB-level backstop.** Username
  and email are now matched case-insensitively at signup (username via
  `__iexact` on the NFKC-normalised value; email via `__iexact` plus
  `_unicode_ci_compare` — the same helper `AccountRecoveryForm.get_users`
  already relies on for recovery), and a per-email Postgres advisory lock
  (`account_tokens.lock_signup_email`) closes the race where two concurrent
  signups for the same email — passkey or password, either combination —
  could otherwise both commit, since `User.email` carries no DB uniqueness
  constraint. But both checks are enforced in application code only, not by
  a database constraint, so they only stop *new* duplicates: a production
  deploy must first audit existing rows for case-insensitive username/email
  duplicates, the same way the dev-DB audit for this change did before it
  shipped — see commit `f4909c3`.
- **`/o/register/`** (OAuth dynamic client registration) still 500s on a
  deeply nested JSON body — pre-existing, and outside DRF, so
  `user_data/drf_handlers.py`'s `RecursionError` guard does not cover it.
- **No `LOGGING` configuration.** `settings.py` declares no `LOGGING` dict,
  so the many `log.info`/`log.warning`/`log.exception` calls across the
  passkey modules (cloned-authenticator warnings, mail-send failures,
  recursion-limit hits, retried transactions, ...) are not captured by any
  configured handler, and an unhandled 500 is not logged either. Configure
  `LOGGING` before relying on these for incident diagnosis.
- **`/password_reset/` timing.** The response-time difference between a
  known and an unknown email is only partly mitigated by rate limiting, not
  eliminated.
