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
via `Authorization: Token <key>` (apps) or the web session + `X-CSRFToken`.
OAuth bearer tokens are **rejected** on every account endpoint, so a
read-scoped MCP connector token can never manage passkeys.

| Endpoint | Auth | Body | Success | Errors |
|---|---|---|---|---|
| `POST /api/passkeys/login/begin/` | none | `{}` | 200 ceremony | 400 malformed body; 429 |
| `POST /api/passkeys/login/finish/` | none | ceremony | 200 `{"key": "<token>"}` (same shape as `/rest-auth/login/`) | 400 `{"non_field_errors": [msg]}` — bad credentials, or "account not active" (see below); 400 malformed body; 429 |
| `POST /login/passkey/` | anon, CSRF | `{challenge_id, credential, next}` | 200 `{"redirect": <safe target>}` + session cookie (`Cache-Control: no-store`) | 400 `{"detail": msg}` — same two messages as above; 403 CSRF failure; 429 (nginx only — this is a plain Django view, so the DRF `passkey` throttle never runs here) |
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
- Signed-in passkey management — the rest of `/api/passkeys/*` (list,
  rename, delete, register, remove password) — **60 req/min, burst 20**.
- `/password_reset/` and the `/reset/<uidb64>/...` confirm pages (reached
  when a client opens the recovery link in an in-app browser, not through
  the JSON API): **GET 20 req/min burst 10**, **POST 5 req/min burst 3** —
  method-aware, since a normal recovery is already GET → GET → POST.

A throttled nginx request on any passkey/recovery location gets
`429 {"error":"rate_limited","retry_after":1,"detail":"Too many requests. Please wait a moment and try again."}`
(the `detail` key is additive over `error`/`retry_after`, for a client that
just displays that field generically). The one exception is
`/password_reset/`/`/reset/.../` — that surface is a browser following an
emailed link, not a script, so its 429 is a small HTML page instead of JSON.

**DRF**, layered underneath (`REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['passkey']`,
currently **20/min**): per authenticated user on account endpoints, per
client IP otherwise. This throttle is per gunicorn worker (no shared cache
across workers — see the design doc's Component 1), so it is a second,
looser-in-practice safety net behind nginx's zone, not the primary control;
`NUM_PROXIES: 1` is set so it keys on the real client IP (the last entry of
`X-Forwarded-For`) rather than letting a client spoof a fresh IP on every
request.

## Testing native clients

Native passkeys need the association files over real HTTPS; `localhost` does
not work. Test against production, or expose a dev stack through an HTTPS
tunnel and set `PASSKEY_RP_ID` / `PASSKEY_WEB_ORIGIN` to the tunnel host.

Internal engineers: `tests/passkey_e2e.py` exercises the whole server-side
flow (password login → step-up → register → passkey login → recovery →
lockout guards) against a running stack, and `tests/passkey_js_test.mjs`
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
