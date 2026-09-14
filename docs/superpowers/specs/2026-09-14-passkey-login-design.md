# Passkey Login — Design

**Date:** 2026-09-14
**Status:** Approved (design); implementation pending
**Related:** [[2026-09-14-remote-mcp-oauth-design]] (the OAuth consent flow reuses
the web login, so passkey web login must honour its `next`).

## Goal

Let E-Tipitaka users sign in with **passkeys** (WebAuthn / FIDO2) from the iOS
app, the Android app and the web, and let **existing users link a passkey to
the account they already have** so they keep all their synced data.

Decisions locked with the user:
- **Passkeys, not passphrases.** Standard WebAuthn discoverable credentials.
- **Clients in v1:** iOS app (native), Android app (native), web login page.
  This repo delivers the server, the web UI and a client-integration doc; the
  native app code lives in the apps' own repos.
- **New users sign up with a passkey and an email.** No password. Email stays
  verified (as today) and is the recovery channel.
- **Old users keep their password after linking** and may remove it later,
  but only while at least one passkey exists.
- **Approach A:** the `webauthn` library (py_webauthn, Duo Labs) plus a small
  in-house Django module. Rejected: `django-otp-webauthn` (2FA-first, pulls the
  `django-otp` stack, browser-session views that native apps cannot use, its
  templates would need an AngularJS XSS audit) and `django-passkeys` (web-only,
  less maintained).
- **Step-up before linking:** registering a passkey on a logged-in account
  requires the current password or a fresh passkey assertion.
- **Recovery extends the existing password reset flow** rather than adding a
  second one.

## Background: what exists today

- **Accounts** are stock `django.contrib.auth.models.User`. No custom user
  model.
- **Password login, two shapes:**
  - `POST /rest-auth/login/` → `{"key": <DRF token>}` for the apps. Throttled
    by the `login` scope (10/min per IP). `Token.objects.get_or_create`, so one
    token per user shared across devices; `/rest-auth/logout/` deletes it.
  - `POST /login/` → Django session for the web. Honours `next` through
    `_safe_redirect_target` (the OAuth `/o/authorize/` flow depends on this).
- **Signup:** `POST /rest-auth/registration/` creates an inactive user and sends
  a signed verification link (`TimestampSigner`, 3 days). Login is refused until
  the email is verified.
- **Password reset:** stock Django views, root-mounted via
  `django.contrib.auth.urls`, with project templates under
  `templates/registration/`. `PasswordResetForm.get_users()` silently skips any
  user whose password is unusable — a passkey-only user would get no email.
- **Web UI:** AngularJS 1.x + jQuery + Bootstrap, no bundler, JS in
  `app/assets/`. `base.html` boots `ng-app` with `<[ ]>` delimiters, so any
  client-supplied text reaching the DOM before bootstrap must be
  `ng-non-bindable`.
- **Runtime:** gunicorn with 3 workers, **no `CACHES` configured** (per-worker
  LocMem). Anything that must survive between two HTTP requests goes in the
  database.
- **Issuer:** `OAUTH_ISSUER_URL` defaults to `https://data.etipitaka.com` and is
  not overridden in dev.
- **iOS app:** team `A6DJDJ7527`, bundle `com.watnapp.E-Tipitaka-Plus`.

## Architecture

```
iOS app ─┐  AuthenticationServices          ┌─ /.well-known/apple-app-site-association
Android ─┼─ Credential Manager      ──JSON──┤  /.well-known/assetlinks.json
Browser ─┘  navigator.credentials           │
                                            ▼
                         passkey_views.py (DRF function views, thin)
                         recovery.py      (reset form, token generator, views)
                                            │
                                            ▼
                         passkey_service.py (ceremonies; no HTTP objects)
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                   webauthn==3.0.0               Passkey / PasskeyUserHandle /
                   (verify crypto, CBOR,         WebAuthnChallenge (PostgreSQL)
                    origin, RP ID, counter)
```

Every ceremony is two calls. **begin** returns
`{"challenge_id": ..., "options": <PublicKeyCredential*OptionsJSON>}`;
**finish** takes `{"challenge_id": ..., "credential": <*ResponseJSON>}`. The
options and credential are the standard WebAuthn JSON forms that iOS, Android
and browsers all produce and consume.

## Component 1: Dependency and data model

**Dependency:** `webauthn==3.0.0` (Python ≥3.10) pinned in
`app/requirements.txt`. Brings `cbor2`, `cryptography>=49`, `pyOpenSSL`,
`pyasn1`, `pyasn1-modules`.

**Migration:** `user_data/migrations/0005_passkeys.py`. The existing `User`
table is untouched.

### `Passkey` — one row per credential; a user may have many

| Field | Type | Purpose |
|---|---|---|
| `user` | FK `User`, CASCADE | owner |
| `credential_id` | `CharField(max_length=1400)`, base64url, **unique** | lookup during username-less login |
| `public_key` | `BinaryField` | COSE public key |
| `sign_count` | `PositiveBigIntegerField` | clone detection |
| `transports` | `JSONField` (list) | echoed in `allowCredentials` / `excludeCredentials` |
| `aaguid` | `CharField(36)` | authenticator model |
| `backed_up` | `BooleanField` | synced (multi-device) vs device-bound |
| `name` | `CharField(100)` | user label |
| `created_at` | `DateTimeField(auto_now_add)` | |
| `last_used_at` | `DateTimeField(null=True)` | |

Default `name`: the client-supplied `name` if given, else a label from a small
built-in AAGUID map (iCloud Keychain, Google Password Manager, Windows Hello,
1Password, Bitwarden), else `"Passkey"`.

### `PasskeyUserHandle` — `OneToOne(User)`

`handle`: 32 random bytes, used as WebAuthn `user.id`. Not the user pk: the
spec requires the handle to carry no identifying information, and a stable
per-account handle lets an authenticator replace an older passkey for the same
account instead of storing a duplicate. Created on the user's first passkey.

### `WebAuthnChallenge` — single-use ceremony state

| Field | Type | Purpose |
|---|---|---|
| `id` | `CharField(primary_key, max_length=64)`, `secrets.token_urlsafe(32)` | public handle returned to the client |
| `challenge` | `BinaryField`, 32 random bytes | |
| `purpose` | `CharField` choices `login` / `register` / `signup` / `recover` | a challenge only finishes the ceremony it began |
| `user` | FK `User`, null | set for `register` and `recover`; null for `login` and `signup` |
| `payload` | `JSONField` | `signup`: `{username, email, handle}` (handle base64url) |
| `expires_at` | `DateTimeField` | now + `PASSKEY_CHALLENGE_TTL` (300 s) |

**Consumption:** inside `transaction.atomic()`, the finish step loads the row
with `select_for_update()` filtered on `id`, `purpose` and `expires_at > now`,
deletes it, then verifies. A concurrent or repeated finish finds no row → 400.
Rows are deleted before verification, so a failed verification also burns the
challenge.

**Cleanup:** creating any challenge first deletes rows with
`expires_at <= now`. No scheduled job.

**Why the database:** no shared cache exists across the 3 gunicorn workers, and
native clients carry no session cookie.

**Passkey-only users** have `set_unusable_password()`. `has_usable_password()`
is the single source for "does this user have a password".

## Component 2: Settings

| Setting | Default | Notes |
|---|---|---|
| `PASSKEY_RP_ID` | env, else host of `OAUTH_ISSUER_URL` → `data.etipitaka.com` | dev override: `localhost` |
| `PASSKEY_WEB_ORIGIN` | env, else `OAUTH_ISSUER_URL` | dev override: `http://localhost:1338` |
| `PASSKEY_RP_NAME` | `"E-Tipitaka"` | |
| `PASSKEY_IOS_APP_IDS` | env (comma list), else `A6DJDJ7527.com.watnapp.E-Tipitaka-Plus` | |
| `PASSKEY_ANDROID_PACKAGE` | env, empty | |
| `PASSKEY_ANDROID_CERT_SHA256` | env (comma list of colon-hex fingerprints), empty | |
| `PASSKEY_EXPECTED_ORIGINS` | derived: `[PASSKEY_WEB_ORIGIN]` + `android:apk-key-hash:<base64url(sha256 bytes)>` per Android fingerprint | iOS native sends `https://<rp id>`, already covered by the web origin |
| `PASSKEY_CHALLENGE_TTL` | `300` | seconds |
| `REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['passkey']` | `'20/min'` | set to `None` under pytest, like `login` |

Android values and the dev localhost overrides go in each environment's
**gitignored** `docker-compose.override.yml`, never the tracked `.env` (same
rule as canon and SMTP): the deploy's `git pull --ff-only` must never see them.

## Component 3: Service layer (`passkey_service.py`)

Plain functions; they take users, dicts and settings, never `request`. Views
translate their exceptions into HTTP codes.

- `begin_login() -> (challenge_id, options)` — `allowCredentials` empty,
  `userVerification=required`.
- `finish_login(challenge_id, credential) -> User` — find `Passkey` by
  `credential.id`; require `response.userHandle` present and equal to the
  owner's handle; `verify_authentication_response(...,
  expected_rp_id, expected_origin=PASSKEY_EXPECTED_ORIGINS,
  credential_public_key, credential_current_sign_count,
  require_user_verification=True)`. The library rejects a non-increasing
  counter whenever either value is non-zero. Then update `sign_count`,
  `backed_up`, `last_used_at`, and `user.last_login`. Inactive owner →
  `InactiveUser`. Any other failure → `InvalidCredentials`.
- `verify_step_up(user, password=None, assertion=None)` — true if
  `password` is given, the user has a usable password and `check_password`
  passes; or if `assertion` (a `{challenge_id, credential}` from
  `begin_login`) verifies as `finish_login` would **and** its passkey belongs
  to `user`. Otherwise `StepUpFailed`.
- `begin_register(user) -> (challenge_id, options)` — `residentKey=required`,
  `userVerification=required`, `attestation=none`, `excludeCredentials` = the
  user's passkeys, `user.name` / `displayName` = username.
- `finish_register(user, challenge_id, credential, name=None) -> Passkey` —
  `verify_registration_response(..., require_user_verification=True)`;
  reject if the `credential_id` already exists on any account; store the row;
  send the "new passkey added" email.
- `begin_signup(username, email) -> (challenge_id, options)` — validate with
  the same rules as `RegisterSerializer` plus Django's
  `UnicodeUsernameValidator`; generate the handle; keep
  `{username, email, handle}` in `payload`. **No `User` row yet.**
- `finish_signup(challenge_id, credential, name=None) -> User` — in one
  transaction: re-check username and email uniqueness, create
  `User(is_active=False)` with an unusable password, the handle and the
  passkey. The view then sends the existing verification email. A name or
  email taken since `begin` → `SignupConflict` (400).
- `list_passkeys(user)`, `rename_passkey(user, id, name)`,
  `delete_passkey(user, id)` — lookups scoped to `user` (else `NotFound`).
  Delete takes `select_for_update()` on the `User` row and refuses to remove
  the last passkey of a user with no usable password (`LockoutGuard`).
- `remove_password(user, password)` — `check_password` required; under
  `select_for_update()` on the user, requires at least one passkey
  (`LockoutGuard`) and a usable password (`LockoutGuard`); then
  `set_unusable_password()`.
- `begin_recover(user)` / `finish_recover(user, challenge_id, credential)` —
  as register, purpose `recover`, followed by `revoke_all_tokens(user)`.
- `revoke_all_tokens(user)` — delete the user's DRF `Token` and
  django-oauth-toolkit access tokens, refresh tokens and grants.

## Component 4: HTTP API

All JSON. "Anon" endpoints use `authentication_classes([])` and the `passkey`
throttle. "Account" endpoints use `TokenAuthentication` and
`SessionAuthentication` only — **OAuth bearer tokens are not accepted**, so a
read-scoped MCP connector token can never manage credentials.

| Method + path | Auth | Request | Success | Errors |
|---|---|---|---|---|
| `POST /api/passkeys/login/begin/` | anon | `{}` | 200 `{challenge_id, options}` | 429 |
| `POST /api/passkeys/login/finish/` | anon | `{challenge_id, credential}` | 200 `{"key": <token>}` (same shape as `/rest-auth/login/`) | 400 `{"non_field_errors": [...]}` — same messages as `LoginSerializer` for bad credentials and inactive account |
| `POST /login/passkey/` | anon, **CSRF** | `{challenge_id, credential, next}` | 200 `{"redirect": <_safe_redirect_target(next)>}` + session | 400 `{"detail": ...}`, 403 CSRF |
| `POST /api/passkeys/register/begin/` | account | `{"password": ...}` or `{"step_up": {challenge_id, credential}}` | 200 `{challenge_id, options}` | 400 step-up failed |
| `POST /api/passkeys/register/finish/` | account | `{challenge_id, credential, name?}` | 201 passkey object | 400 |
| `POST /api/passkeys/signup/begin/` | anon | `{username, email}` | 200 `{challenge_id, options}` | 400 field errors |
| `POST /api/passkeys/signup/finish/` | anon | `{challenge_id, credential, name?}` | 201 `{"detail": "Verification e-mail sent."}` | 400 |
| `GET /api/passkeys/` | account | — | 200 `{has_password, passkeys: [passkey…]}` | 401 |
| `PATCH /api/passkeys/<id>/` | account | `{name}` | 200 passkey object | 400, 404 |
| `DELETE /api/passkeys/<id>/` | account | — | 204 | 404, 409 |
| `POST /api/passkeys/password/remove/` | account | `{password}` | 200 `{"has_password": false}` | 400 wrong password, 409 |
| `POST /account/recover/passkey/begin/` | anon, **CSRF**, reset session | `{uidb64}` | 200 `{challenge_id, options}` | 400 invalid/expired link |
| `POST /account/recover/passkey/finish/` | anon, **CSRF**, reset session | `{uidb64, challenge_id, credential, name?}` | 200 `{"redirect": "/account/security/"}` + session | 400 |
| `GET /.well-known/apple-app-site-association` | anon | — | 200 `application/json` | — |
| `GET /.well-known/assetlinks.json` | anon | — | 200 `application/json` | 404 when Android settings empty |

Passkey object:
`{id, name, authenticator, backed_up, created_at, last_used_at}`.

`/login/passkey/` and the recovery finish call `login(request, user,
backend='django.contrib.auth.backends.ModelBackend')`. `password/remove/` calls
`update_session_auth_hash` for session callers, because changing the password
hash would otherwise log out the current session.

Well-known bodies:
- AASA: `{"webcredentials": {"apps": PASSKEY_IOS_APP_IDS}}`. No `applinks`, so
  email links always open in the browser.
- assetlinks: `[{"relation": ["delegate_permission/common.get_login_creds"],
  "target": {"namespace": "android_app", "package_name": ...,
  "sha256_cert_fingerprints": [...]}}]`.

## Component 5: Recovery (extends password reset)

- **`AccountRecoveryForm(PasswordResetForm)`** — `get_users()` returns active
  users matching the email **with or without** a usable password. Inactive
  users stay excluded. The page keeps Django's generic "if an account exists"
  response.
- **`AccountRecoveryTokenGenerator(PasswordResetTokenGenerator)`** — own
  `key_salt`; `_make_hash_value` = Django's value + the pk of the user's newest
  passkey (or empty). The link stops working once a password is set, a passkey
  is added, or the user logs in (`last_login` is already in Django's hash).
  Timeout stays `PASSWORD_RESET_TIMEOUT` (Django default, 3 days).
- **URLs:** explicit `password_reset/` and `reset/<uidb64>/<token>/` paths
  are placed **before** the root `include('django.contrib.auth.urls')`, using
  `PasswordResetView(form_class=AccountRecoveryForm,
  token_generator=..., email_template_name='registration/password_reset_email.txt')`
  and `AccountRecoveryConfirmView(PasswordResetConfirmView)` with the same
  generator. Other auth URLs are unchanged.
- **Email text:** "reset your password or create a new passkey", with Thai
  translation.
- **Confirm page** (`registration/password_reset_confirm.html`, reached at
  `/reset/<uidb64>/set-password/` after Django moves the token into the
  session): a **Create a new passkey** button above the existing set-password
  form.
- **Recovery endpoints** re-validate the token Django stores in the session
  (`INTERNAL_RESET_SESSION_TOKEN`) against `uidb64` on both begin and finish.
- **After passkey recovery:** passkey stored, "new passkey added" email sent,
  `revoke_all_tokens(user)`, logged in on this browser, redirected to
  `/account/security/` to delete the lost device's passkey.
- **After password reset** (existing form): `AccountRecoveryConfirmView`
  additionally calls `revoke_all_tokens(user)`. Django already invalidates
  sessions on password change. This is a behaviour change: other devices must
  sign in again after a reset.
- **Native apps** add no recovery API. "Forgot password / lost passkey" opens
  `https://<rp id>/password_reset/` in `ASWebAuthenticationSession` or a
  Custom Tab. The new passkey is saved under the same RP ID, so the app can
  use it immediately.

## Component 6: Web UI

- **`app/assets/passkey.js`** — vanilla JS, no Angular, no npm. Includes a
  ~40-line base64url encode/decode helper so it works where
  `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON()` are missing.
  Hides every passkey control when `window.PublicKeyCredential` is undefined.
  Sends `X-CSRFToken` on web-session endpoints. Strings come from the existing
  `window.i18n` block in `base.html`.
- **XSS rule:** passkey names and any server text are inserted with
  `textContent` only. Containers that hold them carry `ng-non-bindable`.
- **Login (`login.html`, `forms/login_form.html`):** "Sign in with passkey"
  button above the password form. Username input gets
  `autocomplete="username webauthn"`. If
  `PublicKeyCredential.isConditionalMediationAvailable()` resolves true, the
  page starts a `navigator.credentials.get({mediation: 'conditional'})` so the
  browser offers passkeys in the username autofill; the challenge is re-fetched
  when it expires. Finish posts to `/login/passkey/` with `next`, then follows
  `redirect`.
- **Signup (`signup.html`):** passkey signup is the default (username + email →
  "Create account with passkey" → existing `validate.html` "check your email"
  page). A "Sign up with a password instead" link reveals the existing
  password form.
- **Account security page `/account/security/`** (`account_security.html`,
  `@login_required`, navbar link): lists passkeys (name, synced or
  device-bound, created, last used) with rename and delete; **Add passkey**
  runs step-up (password prompt, or a passkey assertion when `has_password` is
  false) then registration; **Remove password** shows only when
  `has_password` and at least one passkey exist.
- **Recovery confirm page:** Create-a-new-passkey button (Component 5).

## Component 7: Hosting

- **nginx:** new `limit_req_zone` `passkey` (30r/m, burst 10) for
  `^/api/passkeys/` and `= /login/passkey/` and `^/account/recover/passkey/`,
  with a `@ratelimited_passkey` 429 handler and `Retry-After`, matching the
  existing DCR/token zones. The DRF `passkey` throttle stays as a second layer
  but is per worker (no shared cache).
- **`.well-known` paths** already reach Django through `location /`; no nginx
  change needed.
- **`deploy.sh`:** after the existing homepage check, `curl -fsS` the AASA
  endpoint and require a JSON body.
- Migration `0005_passkeys` is applied by the existing
  `manage.py migrate --noinput` step in `deploy.sh`.

## Data flows

**Old user links a passkey (app):** password login → token → user taps "Add
passkey" → app sends `register/begin` with `{password}` → OS passkey sheet
(Face ID) → `register/finish` → passkey saved, email sent. Password still works.

**New user (web or app):** `signup/begin {username, email}` → OS sheet →
`signup/finish` → user + passkey created inactive → verification email → user
clicks link (existing `/account/confirm-email/`) → account active → passkey
login works.

**Native login:** `login/begin` → OS shows the account's passkeys → Face ID →
`login/finish` → `{key}` → app continues exactly as after password login.

**Web login inside the OAuth connector flow:** ChatGPT/Claude →
`/o/authorize/` → `login_required` → `/login/?next=/o/authorize/...` → passkey
autofill or button → `/login/passkey/` with `next` → `{redirect}` → consent
page.

**Lost passkey:** `/password_reset/` → email → `/reset/<uidb64>/<token>/` →
`/reset/<uidb64>/set-password/` → Create a new passkey → recovery
begin/finish → all tokens revoked → logged in → `/account/security/` → delete
old passkey.

## Security

| Threat | Control |
|---|---|
| Stolen device used without the owner's biometric or PIN | `userVerification: required` on every ceremony; library rejects a response without the UV flag |
| Phishing, wrong site | library verifies RP ID hash and origin against `PASSKEY_EXPECTED_ORIGINS` |
| Replay | challenge single-use (deleted before verify), 5-minute expiry, bound to `purpose` and `user` |
| Cloned authenticator | library rejects a non-increasing sign counter when either value is non-zero; logged as a warning without credential or challenge values |
| Credential registered to two accounts | `credential_id` unique; registration of an existing id → 400 |
| Login CSRF | `/login/passkey/` and recovery endpoints are CSRF-protected; the token endpoint returns the key in the body and sets no cookie |
| Stolen DRF token turned into a permanent passkey | step-up (password or same-user assertion) plus "new passkey added" email |
| MCP connector token misuse | OAuth bearer tokens are not an accepted authenticator on any passkey endpoint |
| Password guessing through step-up or password removal | covered by the `passkey` throttles; wrong password → 400 with no detail |
| Lockout races | last-credential checks run under `select_for_update()` on the user row |
| Username-less login with a missing or wrong `userHandle` | rejected |
| Account enumeration | login and recovery responses are generic. Signup reveals a taken username or email, **as `/rest-auth/registration/` already does** (accepted) |
| XSS through passkey names or AngularJS interpolation | `textContent` only; `ng-non-bindable` containers; no passkey name rendered by Django templates |
| Lost device still holding tokens | recovery and password reset revoke DRF and OAuth tokens |
| Request flooding | nginx `passkey` zone + DRF `passkey` throttle |

`attestation: none`: the device model is not needed, synced passkeys send no
attestation, and it avoids collecting device identifiers.

## Error handling

| Situation | Response |
|---|---|
| Unknown, expired, reused or wrong-purpose `challenge_id` | 400 |
| Malformed credential JSON | 400 (library `InvalidRegistrationResponse` / `InvalidAuthenticationResponse`, or parse error) |
| Verification failure on login | 400 with the generic `LoginSerializer` message |
| Inactive account on login | 400 with the existing "verify your email" message |
| Step-up failed | 400 |
| Signup name/email taken (at begin or finish) | 400 with field errors |
| Passkey id not owned by caller | 404 |
| Deleting the last passkey without a password; removing a password without a passkey | 409 |
| Missing or invalid recovery session token | 400 |
| Android settings empty | `assetlinks.json` 404; no Android origin accepted |
| Throttled | 429 (DRF) or nginx 429 with `Retry-After` |

## Testing

**Unit (pytest-django, 90% coverage gate)**
- `user_data/tests/soft_authenticator.py` — a software authenticator built on
  `cryptography` and `cbor2`. Produces real ES256 `none`-attestation
  registration responses and signed assertions with correct `clientDataJSON`,
  RP ID hash, flags (UP, UV, BE, BS) and counter. Parameters for tampering:
  origin, RP ID, UV flag off, signature corrupted, counter regression,
  `userHandle` wrong or missing.
- `test_passkey_service.py` — every ceremony's happy path and each tamper
  case; challenge reuse, expiry and purpose mismatch; duplicate credential id;
  signup race; lockout guards; token revocation.
- `test_passkey_views.py` — authentication matrix (Token and Session accepted;
  OAuth bearer and anonymous rejected on account endpoints); login token shape
  equals `rest_login`'s; CSRF enforced on `/login/passkey/`; unsafe `next` →
  `/`; step-up by password and by assertion, and by another user's assertion
  (rejected); 400/404/409 codes; username validator; verification and
  "passkey added" emails in `mail.outbox`; session survives password removal.
- `test_passkey_recovery.py` — unusable-password users receive the reset email;
  inactive users do not; link invalid after a passkey is added or a password is
  set; tokens revoked on both paths; missing or wrong session token → 400.
- `test_wellknown.py` — AASA body and content type; assetlinks 404 when unset
  and body when set; Android origin derived correctly from a colon-hex
  fingerprint; `PASSKEY_RP_ID` / `PASSKEY_WEB_ORIGIN` defaults and overrides.
- `test_models.py` — new models and constraints.

**Golden harness (HTTP, same-stack)**
- `normalize.py` masks `challenge`, `challenge_id` and `user.id` values as
  `<CHALLENGE>`, with a `test_normalize.py` case.
- New cases: `apple_app_site_association`, `assetlinks_unset`,
  `passkey_login_begin`, `passkey_login_finish_bad_challenge`,
  `passkeys_list_anon`, `passkeys_list_alice` (empty list, `has_password: true`).
- README localization note lists them as same-stack.

**End-to-end: `tests/passkey_e2e.py`** (like `tests/oauth_e2e.py`, against the
local stack, using the software authenticator with the default RP values, so
no dev override is required)
- Seeded alice: password login → step-up with password → register passkey →
  passkey login → `/rest-auth/user/` returns alice.
- Web: fetch CSRF, start `/o/authorize/` to obtain `next`, finish via
  `/login/passkey/` → `redirect` lands on the consent page.
- Guards: remove password → delete the only passkey → 409.

**Manual acceptance after deploy**
- Apple CDN copy `https://app-site-association.cdn-apple.com/a/v1/data.etipitaka.com`
  matches the served AASA.
- Web signup, passkey login (button and autofill), link from an old account,
  and recovery on Safari macOS, Safari iPhone and Chrome Android.
- Native apps: verified in their own repos against
  `docs/passkeys-client-integration.md`.

## Deliverables

- `app/requirements.txt` — `webauthn==3.0.0`.
- `app/user_data/models.py`, `migrations/0005_passkeys.py`.
- `app/user_data/passkey_service.py`, `passkey_views.py`, `recovery.py`,
  `wellknown_views.py`.
- `app/etipitaka_auth/settings.py`, `urls.py`.
- Templates: `account_security.html`, `login.html` / `forms/login_form.html`,
  `signup.html` / `forms/signup_form.html`,
  `registration/password_reset_confirm.html`,
  `registration/password_reset_email.txt`, `email/passkey_added.txt`,
  `base.html` (navbar link, i18n strings, script tag).
- `app/assets/passkey.js`.
- `app/locale/th/LC_MESSAGES/django.po` (+ compiled `.mo`).
- `nginx/nginx.conf`, `deploy.sh`.
- Tests listed above; golden snapshots and README note.
- `docs/passkeys-client-integration.md` — endpoints, JSON shapes, iOS
  entitlement `webcredentials:data.etipitaka.com`, Android assetlinks and
  Credential Manager notes, step-up and recovery flows, error codes, testing
  against prod or an HTTPS tunnel (native passkeys cannot use `localhost`).

## Out of scope (v1)

- iOS and Android app code.
- Deleting existing web sessions on passkey recovery (Django sessions are not
  indexed by user; would need a full session scan).
- WebAuthn Signal API (`signalUnknownCredential`, etc.).
- A resend-verification-email endpoint.
- Passkeys as a second factor on top of a password.
- Attestation verification / authenticator allow-listing.

## Risks / notes

- **Token model:** DRF tokens are shared per user and never expire. Passkeys do
  not change that; step-up and revocation-on-recovery narrow the damage of a
  leaked token but do not remove it.
- **Throttle accuracy** depends on the still-open host-proxy item
  (`X-Forwarded-For` + `TRUST_PROXY_PROTO`): until it is done, nginx buckets
  clients together, so the `passkey` zone may throttle many users as one.
- **Local browser testing** requires the dev override
  (`PASSKEY_RP_ID=localhost`, `PASSKEY_WEB_ORIGIN=http://localhost:1338`);
  passkeys created locally are tied to `localhost` and do not work on prod.
- **`cryptography>=49`** is required by `webauthn==3.0.0`; the image build must
  resolve it alongside django-oauth-toolkit's dependencies. If it conflicts,
  `webauthn==2.8.0` has the same API.
- **Orphan passkeys:** if a finish call fails after the authenticator created
  the credential (signup race, network loss), the passkey remains in the
  user's password manager with no server row. Login with it returns the
  generic error. Acceptable for v1.
