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

**Migration:** `user_data/migrations/0005_passkeys.py`, plus
`migrations/0006_passkey_epoch.py` (`PasskeyEpoch`, added later for
Component 5's reset-token hash). The existing `User` table is untouched.

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
built-in AAGUID map (Apple Passwords, iCloud Keychain (Managed), Google
Password Manager, Windows Hello, 1Password, Bitwarden), else `"Passkey"`.
**PASSKEY_MAX_PER_USER = 20**: register/begin and register/finish (never
signup or recovery, so a filled account can never block its own owner's
recovery) reject a 21st passkey with a 409, `"You have reached the maximum
number of passkeys."`.

### `PasskeyUserHandle` — `OneToOne(User)`

`handle`: 32 random bytes, used as WebAuthn `user.id`. Not the user pk: the
spec requires the handle to carry no identifying information, and a stable
per-account handle lets an authenticator replace an older passkey for the same
account instead of storing a duplicate. Created at **begin**, not at the
first stored passkey: `begin_register`/`begin_recover` create the row via
`get_or_create` the first time either ceremony runs for a user; `begin_signup`
generates the handle immediately and carries it in the challenge payload
until `finish_signup` persists the row.

### `PasskeyEpoch` — `OneToOne(User)`

`value`: a monotonic per-user counter, bumped by one, under the user row's
`select_for_update()` lock, every time a passkey is added (`_store_passkey`)
or deleted (`passkey_manage.delete_passkey`). Exists solely so
`AccountRecoveryTokenGenerator` (Component 5) can mix in a value that only
ever increases — the *current* passkey set (e.g. its newest pk) can go back
down if a passkey is added then deleted, which would quietly revive a reset
token that the add had correctly killed.

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
| `passkey_config.expected_origins()` | derived: `[PASSKEY_WEB_ORIGIN]` + `android:apk-key-hash:<base64url(sha256 bytes)>` per Android fingerprint | iOS native sends `https://<rp id>`, already covered by the web origin |
| `PASSKEY_CHALLENGE_TTL` | `300` | seconds |
| `REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['passkey']` | `'20/min'` | set to `None` under pytest, like `login` |
| `REST_FRAMEWORK['NUM_PROXIES']` | `1` | pins DRF's IP-keyed throttles to the last `X-Forwarded-For` entry (the one this container's own nginx appends) instead of the whole client-controlled header, which would otherwise let a client dodge the bucket by spoofing a fresh address every request |

Android values and the dev localhost overrides go in each environment's
**gitignored** `docker-compose.override.yml`, never the tracked `.env` (same
rule as canon and SMTP): the deploy's `git pull --ff-only` must never see them.

`PASSKEY_RP_ID` and `PASSKEY_WEB_ORIGIN` are stripped of surrounding
whitespace when read from the environment, so a stray space in a compose
file cannot silently produce a broken relying party. A Django system check
(`user_data/checks.py`, registered from `UserDataConfig.ready`) validates
`PASSKEY_ANDROID_PACKAGE`/`PASSKEY_ANDROID_CERT_SHA256` at boot: each
fingerprint must decode to 32 bytes (the same rule
`passkey_config.android_origin` enforces at request time), and the two
settings must be either both set or both empty. A misconfiguration fails
`manage.py check` with a clear message instead of surfacing later as a 500
at login or a silently 404'd `assetlinks.json`.

## Component 3: Service layer (`passkey_service.py`)

Plain functions; they take users, dicts and settings, never `request`. Views
translate their exceptions into HTTP codes.

- `begin_login() -> (challenge_id, options)` — `allowCredentials` empty,
  `userVerification=required`.
- `finish_login(challenge_id, credential) -> User` — find `Passkey` by
  `credential.id`; require `response.userHandle` present and equal to the
  owner's handle; `verify_authentication_response(...,
  expected_rp_id, expected_origin=passkey_config.expected_origins(),
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
- `begin_signup(username, email) -> (challenge_id, options)` — validated by
  `AccountIdentitySerializer` (username ≤150 chars + Django's
  `UnicodeUsernameValidator` + uniqueness; email ≤254 chars + uniqueness) —
  the same serializer `RegisterSerializer` (password signup) now extends, so
  the two signup paths can't drift apart; generate the handle; keep
  `{username, email, handle}` in `payload`. **No `User` row yet.** The
  username is NFKC-normalized (`User.normalize_username`) before the
  uniqueness check and before it is stored, and both username and email are
  matched case-insensitively (`__iexact` on the normalized username;
  `__iexact` plus `_unicode_ci_compare` for email — the same helper
  `AccountRecoveryForm.get_users` already relies on). This closes the gap
  the client guide's "Known gaps" used to describe; see that guide for the
  production-rollout caveat (no DB-level unique index backs either check).
- `finish_signup(challenge_id, credential, name=None) -> User` — consumes and
  verifies the challenge, then opens a transaction and takes a per-email
  Postgres advisory lock (`account_tokens.lock_signup_email`) as its very
  first statement, *before* re-checking username and email uniqueness, and
  only then creates `User(is_active=False)` with an unusable password, the
  handle and the passkey, all inside that same transaction. The view then
  sends the existing verification email. A name or email taken since
  `begin` → `SignupInvalid` (400, field errors). `RegisterSerializer.create`
  (password signup) takes the same lock, under the same namespace, before
  its own re-check, so a passkey signup and a password signup racing for
  the same email are serialised against each other too, not just against
  their own kind — closing the concurrent-same-email-signup race the client
  guide's "Known gaps" used to describe. (Username needs no equivalent
  lock: the database's own unique index on username still catches an
  exact-duplicate race as an `IntegrityError`.)
- `list_passkeys(user)`, `rename_passkey(user, id, name)`,
  `delete_passkey(user, id)` — lookups scoped to `user` (else `NotFound`).
  Delete takes `select_for_update()` on the `User` row and refuses to remove
  the last passkey of a user with no usable password (`LockoutGuard`); on
  success it sends the "passkey deleted" email, best-effort, strictly after
  the deleting transaction has committed (`passkey_manage.delete_passkey`).
- `remove_password(user, password)` — `check_password` required; under
  `select_for_update()` on the user, requires at least one passkey
  (`LockoutGuard`) and a usable password (`LockoutGuard`); then
  `set_unusable_password()`. Deliberately does **not** call
  `revoke_all_tokens`: an existing DRF token keeps working after the
  password fallback is dropped; only recovery (below) revokes tokens. Sends
  the "password removed" email, best-effort, strictly after the transaction
  commits.
- `begin_recover(user)` / `finish_recover(user, challenge_id, credential)` —
  as register, purpose `recover`, followed by `revoke_all_tokens(user)` *and*
  `delete_user_sessions(user, keep_session_key=...)` (the recovering
  browser's own, freshly-cycled session is kept; every other browser session
  for the account is deleted — see Component 5, which also covers why this
  runs as two separate transactions, not one).
- `revoke_all_tokens(user)` — delete the user's DRF `Token` and
  django-oauth-toolkit access tokens, refresh tokens and grants. Takes a
  per-user Postgres advisory lock (`account_tokens.lock_user_tokens`) before
  touching any row; `user_data/oauth_validators.py`'s
  `EtipitakaOAuth2Validator` takes the same lock before every
  django-oauth-toolkit token write (issuance, refresh rotation, RFC 7009
  revocation), which is what actually prevents a deadlock between recovery's
  revocation and a concurrent OAuth refresh-token rotation — row-lock
  ordering alone cannot, because Django's delete collector and DOT's own
  rotation code lock `AccessToken`/`RefreshToken` in opposite orders.
- `bump_passkey_epoch(user)` — advance `PasskeyEpoch.value` by one; called by
  every path that adds (`_store_passkey`, inside `register`/`signup`/
  `recover`) or deletes (`passkey_manage.delete_passkey`) a passkey, under
  the same locked transaction. See the `PasskeyEpoch` model above and
  Component 5's token generator.

## Component 4: HTTP API

All JSON. "Anon" endpoints use `authentication_classes([])` and the `passkey`
throttle. "Account" endpoints use `TokenAuthentication` and
`SessionAuthentication` only — **OAuth bearer tokens are not accepted**, so a
read-scoped MCP connector token can never manage credentials.

| Method + path | Auth | Request | Success | Errors |
|---|---|---|---|---|
| `POST /api/passkeys/login/begin/` | anon | `{}` | 200 `{challenge_id, options}` | 429 |
| `POST /api/passkeys/login/finish/` | anon | `{challenge_id, credential}` | 200 `{"key": <token>}` (same shape as `/rest-auth/login/`) | 400 `{"non_field_errors": [...]}` — same message strings as `LoginSerializer` for bad credentials and inactive account, but not the same *reachability*: `finish_login` checks `is_active` explicitly after verifying the assertion, so the inactive-account message is reachable here; on the password path `ModelBackend.authenticate()` already returns `None` for an inactive user, so `LoginSerializer` never gets past the generic bad-credentials branch to reach it |
| `POST /login/passkey/` | anon, **CSRF** | `{challenge_id, credential, next}` | 200 `{"redirect": <_safe_redirect_target(next)>}` + session | 400 `{"detail": ...}`, 403 CSRF |
| `POST /api/passkeys/register/begin/` | account | `{"password": ...}` or `{"step_up": {challenge_id, credential}}` | 200 `{challenge_id, options}` | 400 step-up failed; 409 `PASSKEY_MAX_PER_USER` (20) already reached |
| `POST /api/passkeys/register/finish/` | account | `{challenge_id, credential, name?}` | 201 passkey object | 400; 409 `PASSKEY_MAX_PER_USER` reached (re-checked under lock, so two concurrent finishes can't together exceed it) |
| `POST /api/passkeys/signup/begin/` | anon | `{username, email}` | 200 `{challenge_id, options}` | 400 field errors |
| `POST /api/passkeys/signup/finish/` | anon | `{challenge_id, credential, name?}` | 201 `{"detail": "Verification e-mail sent."}` | 400 |
| `GET /api/passkeys/` | account | — | 200 `{has_password, passkeys: [passkey…]}` | 401 |
| `PATCH /api/passkeys/<id>/` | account | `{name}` | 200 passkey object | 400, 404 |
| `DELETE /api/passkeys/<id>/` | account | — | 204 | 404, 409 |
| `POST /api/passkeys/password/remove/` | account | `{password}` | 200 `{"has_password": false}` | 400 wrong password, 409 |
| `POST /account/recover/passkey/begin/` | anon, **CSRF**, reset session | `{uidb64}` | 200 `{challenge_id, options}` | 400 invalid/expired link |
| `POST /account/recover/passkey/finish/` | anon, **CSRF**, reset session | `{uidb64, challenge_id, credential, name?}` | 200 `{"redirect": "/account/security/"}` + session | 400 |
| `GET /.well-known/apple-app-site-association` | anon | — | 200 `application/json` | 404 JSON when `PASSKEY_IOS_APP_IDS` is empty (an empty `{"webcredentials": {"apps": []}}` would actively tell iOS no app is associated, which is worse than a 404) |
| `GET /.well-known/assetlinks.json` | anon | — | 200 `application/json` | 404 JSON when Android settings empty |

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
  `key_salt`; `_make_hash_value` = Django's value + the user's `PasskeyEpoch`
  counter (or empty, if the user has none yet). The link stops working once a
  password is set, a passkey is **added or removed**, or the user logs in
  (`last_login` is already in Django's hash). A monotonic counter, not the
  newest passkey's pk, is deliberate: "newest pk" can go back down (add a
  passkey — correctly killing the token — then delete it, and the token
  would quietly come back to life); `PasskeyEpoch` only ever increases.
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
- **After passkey recovery:** `revoke_all_tokens(user)`, then the passkey is
  stored and `delete_user_sessions(user, keep_session_key=...)` deletes
  every *other* browser session for the account (the recovering browser
  keeps its own, freshly-cycled session — `request.session.cycle_key()`
  runs first, also defeating session fixation) — as two separate,
  independently retried transactions, not one, to avoid a deadlock against a
  concurrent OAuth refresh-token rotation (see `revoke_all_tokens` and
  `bump_passkey_epoch` above). Then "new passkey added" email sent, logged in
  on this browser, redirected to `/account/security/` to delete the lost
  device's passkey. This is a deliberate behaviour change from the original
  design: browser sessions on other devices are now deleted here too, not
  left as future work (see "Out of scope" below).
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

- **nginx** (superseded by Task 23; full rationale in
  `docs/remote-mcp-oauth-deploy.md`, summarized in
  `docs/passkeys-client-integration.md`'s "Rate limits" section — not the
  single 30r/m-burst-10 `passkey` zone originally planned here):
  - `passkey_rl` (60r/m, burst 30) for the anonymous surface —
    `^/api/passkeys/(login|signup)/`, `^/login/passkey/?$` and
    `^/account/recover/passkey/` — via `@ratelimited_passkey`.
  - `passkey_manage_rl` (60r/m, burst 20) for the rest of
    `^/api/passkeys(/|$)` (signed-in list/rename/delete/register/remove
    password) via `@ratelimited_passkey_manage`.
  - `reset_get_rl` (20r/m, burst 10) and `reset_post_rl` (5r/m, burst 3),
    method-aware, for `/password_reset/` and `/reset/<uidb64>/<token-or-
    set-password>/`, via `@ratelimited_reset` — the only 429 handler on this
    surface that renders HTML instead of JSON, since it's reached by a
    browser following an emailed link.
  - Every location above caps the request body at 64 KiB
    (`client_max_body_size 64k`).
  - The DRF `passkey` throttle stays as a second layer but is per worker (no
    shared cache); `REST_FRAMEWORK['NUM_PROXIES'] = 1` was added so it keys
    on the real client IP instead of a client-spoofable header.
- **`.well-known` paths** already reach Django through `location /`; no nginx
  location of their own, so they are never rate-limited.
- **`TRUST_PROXY_PROTO=1`** (a separate, opt-in operator setting, not
  passkey-specific) additionally marks `SESSION_COOKIE_SECURE` and
  `CSRF_COOKIE_SECURE`, once the front-most proxy is confirmed to always
  overwrite `X-Forwarded-Proto`. See `docs/remote-mcp-oauth-deploy.md`.
- **`deploy.sh`:** after the existing homepage check, `curl -fsS` the AASA
  endpoint and require a JSON body.
- Migrations `0005_passkeys` and `0006_passkey_epoch` are applied by the
  existing `manage.py migrate --noinput` step in `deploy.sh`.

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
begin/finish → all tokens revoked and every other browser session deleted →
logged in on this browser → `/account/security/` → delete old passkey.

## Security

| Threat | Control |
|---|---|
| Stolen device used without the owner's biometric or PIN | `userVerification: required` on every ceremony; library rejects a response without the UV flag |
| Phishing, wrong site | library verifies RP ID hash and origin against `passkey_config.expected_origins()` |
| Replay | challenge single-use (deleted before verify), 5-minute expiry, bound to `purpose` and `user` |
| Cloned authenticator | library rejects a non-increasing sign counter when either value is non-zero; logged as a warning without credential or challenge values |
| Credential registered to two accounts | `credential_id` unique; registration of an existing id → 400 |
| Login CSRF | `/login/passkey/` and recovery endpoints are CSRF-protected; the token endpoint returns the key in the body and sets no cookie |
| Stolen DRF token turned into a permanent passkey | step-up (password or same-user assertion) plus "new passkey added" email |
| Stolen session adds a passkey, drops the password, then deletes the owner's passkeys without the owner noticing | "passkey deleted" and "password removed" emails, best-effort, alongside "passkey added" — all three notify the account's email, not just the addition |
| MCP connector token misuse | OAuth bearer tokens are not an accepted authenticator on any passkey endpoint |
| Password guessing through step-up or password removal | covered by the `passkey` throttles; wrong password → 400 with no detail |
| Lockout races | last-credential checks run under `select_for_update()` on the user row |
| Username-less login with a missing or wrong `userHandle` | rejected |
| Account enumeration | login and recovery responses are generic. Signup reveals a taken username or email, **as `/rest-auth/registration/` already does** (accepted) |
| XSS through passkey names or AngularJS interpolation | `textContent` only; `ng-non-bindable` containers; no passkey name rendered by Django templates |
| Lost device still holding tokens | recovery and password reset revoke DRF and OAuth tokens; passkey recovery (not password reset) also deletes every other browser session |
| Request flooding | nginx (separate zones for anonymous ceremonies, signed-in management, and the password-reset GET/POST pages — see Component 7) plus the DRF `passkey` throttle as a second, per-worker layer |

`attestation: none`: the device model is not needed, synced passkeys send no
attestation, and it avoids collecting device identifiers.

## Error handling

| Situation | Response |
|---|---|
| Unknown, expired, reused or wrong-purpose `challenge_id` | 400 |
| Malformed credential JSON | 400 (library `InvalidRegistrationResponse` / `InvalidAuthenticationResponse`, or parse error) |
| Request body isn't a JSON object, or nests too deeply to parse | 400 `{"detail": "Malformed request."}` — every `/api/passkeys/*` (DRF) endpoint via a shared `_body()` guard, plus a project-wide `EXCEPTION_HANDLER` (`user_data/drf_handlers.py`) for the deep-nesting case; `/login/passkey/` and `/account/recover/passkey/*` are plain Django views, not DRF, so they instead treat such a body as `{}` and fall through to their own domain-specific 400 |
| Verification failure on login | 400 with the generic `LoginSerializer` message |
| Inactive account on login | 400 with the existing "verify your email" message — reachable on the passkey path; not reachable on the password path, since `ModelBackend` returns `None` for an inactive user before `LoginSerializer` gets there (see Component 4's login/finish row) |
| Step-up failed | 400 |
| Signup name/email taken (at begin or finish) | 400 with field errors |
| Passkey id not owned by caller | 404 |
| Deleting the last passkey without a password; removing a password without a passkey | 409 `"Your account must keep at least one way to sign in."` |
| Passkey cap (`PASSKEY_MAX_PER_USER` = 20) reached, at register/begin or register/finish only | 409 `"You have reached the maximum number of passkeys."` |
| Missing or invalid recovery session token | 400 |
| Android settings empty | `assetlinks.json` 404; no Android origin accepted |
| `PASSKEY_IOS_APP_IDS` empty | `apple-app-site-association` 404 |
| Throttled | 429 (DRF `passkey` throttle) or nginx 429 (JSON with `Retry-After` on every passkey zone; the `/password_reset/`/reset-confirm zone renders a small HTML page instead — see Component 7) |

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
- `test_recovery.py` (named `test_passkey_recovery.py` in the original plan)
  — unusable-password users receive the reset email; inactive users do not;
  link invalid after a passkey is added **or removed**, a password change, a
  login, or an email change (`PasskeyEpoch` + Django's own hash inputs);
  tokens revoked and other browser sessions deleted on both recovery paths;
  the recovering browser keeps its own session; missing or wrong session
  token → 400; deadlock-retry behaviour against a concurrent OAuth
  refresh-token rotation.
- `test_wellknown.py` — AASA body and content type; assetlinks 404 when unset
  and body when set; AASA itself 404 when `PASSKEY_IOS_APP_IDS` is empty;
  Android origin derived correctly from a colon-hex fingerprint;
  `PASSKEY_RP_ID` / `PASSKEY_WEB_ORIGIN` defaults and overrides.
- `test_models.py` / `test_passkey_models.py` — new models and constraints.
- Split further, beyond what this plan originally called out as one file per
  concern: `test_passkey_config.py`, `test_passkey_challenges.py`,
  `test_passkey_manage.py`, `test_passkey_pages.py`, `test_passkey_web.py`,
  `test_passkey_i18n.py`, `test_serializers.py` — covering, among other
  things, the `PASSKEY_MAX_PER_USER` cap (both register endpoints, and the
  race between two concurrent finishes), the `_bad_request()` /
  `drf_handlers.py` malformed-body 400, `NUM_PROXIES` pinning the DRF
  throttle to the real client IP despite a spoofed `X-Forwarded-For`, and
  `TRUST_PROXY_PROTO`'s cookie-security behaviour.
- `tests/passkey_js_test.mjs` (run on the host with Node, not in the `web`
  container) — unit tests for `app/assets/passkey.js`'s private helpers,
  plus a `node --check` syntax pass over every `passkey*.js` file and
  `account_security.js`. See `tests/README.md`.

**Golden harness (HTTP, same-stack)**
- `normalize.py` masks `challenge` and `challenge_id` values as
  `<CHALLENGE>` (it does not mask `user.id`), with a `test_normalize.py` case.
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
- `app/user_data/models.py`, `migrations/0005_passkeys.py`,
  `migrations/0006_passkey_epoch.py` (`PasskeyEpoch`).
- `app/user_data/passkey_config.py`, `passkey_challenges.py`,
  `passkey_service.py`, `passkey_manage.py`, `account_tokens.py`,
  `passkey_views.py`, `passkey_web_views.py`, `wellknown_views.py`,
  `recovery.py`; `serializers.py` (`AccountIdentitySerializer`).
- `app/user_data/oauth_validators.py` — the per-user advisory-lock
  `EtipitakaOAuth2Validator`, wired in via
  `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']`, that serialises every
  django-oauth-toolkit token write against passkey recovery's own
  `revoke_all_tokens` (not called out in the original plan — needed once
  recovery's token revocation started deadlocking against a live OAuth
  refresh-token rotation under load).
- `app/user_data/drf_handlers.py` — the project-wide DRF `EXCEPTION_HANDLER`
  that maps a pathologically deep JSON body (`RecursionError`) to the same
  clean 400 the passkey endpoints already give a wrong-shaped body.
- `app/etipitaka_auth/settings.py`, `urls.py`.
- Templates: `account_security.html`, `login.html`, `forms/login_form.html`,
  `signup.html`, `registration/password_reset_confirm.html`,
  `registration/password_reset_email.txt`, `email/passkey_added.txt`,
  `email/passkey_deleted.txt`, `email/password_removed.txt`, `base.html`.
- `app/assets/passkey.js`, `passkey_login.js`, `passkey_signup.js`,
  `account_security.js`, `passkey_recover.js`.
- `app/locale/th/LC_MESSAGES/django.po` (+ compiled `.mo`).
- `nginx/nginx.conf`, `deploy.sh` (rate-limit zones reworked again by Task
  23 — see Component 7).
- Unit tests (see Testing above — more files than this plan originally
  listed), golden snapshots + README note, `tests/passkey_e2e.py`,
  `tests/passkey_js_test.mjs`, `tests/README.md`.
- `docs/passkeys-client-integration.md` — endpoints, JSON shapes, iOS
  entitlement `webcredentials:data.etipitaka.com`, Android assetlinks and
  Credential Manager notes, step-up and recovery flows, rate limits and 429
  shapes, error codes, "Known gaps", testing against prod or an HTTPS
  tunnel (native passkeys cannot use `localhost`).
- Plan: `docs/superpowers/plans/2026-09-14-passkey-login.md`.

## Out of scope (v1)

- iOS and Android app code.
- WebAuthn Signal API (`signalUnknownCredential`, etc.).
- A resend-verification-email endpoint.
- Passkeys as a second factor on top of a password.
- Attestation verification / authenticator allow-listing.

## Risks / notes

- **Token model:** DRF tokens are shared per user and never expire. Passkeys do
  not change that; step-up and revocation-on-recovery narrow the damage of a
  leaked token but do not remove it.
- **Throttle accuracy**, originally an open item here, was closed within
  this repo by Task 23: `nginx/nginx.conf` now recovers the real client
  address from `X-Forwarded-For` (`set_real_ip_from` / `real_ip_recursive`)
  before keying any `limit_req_zone` on it, and
  `REST_FRAMEWORK['NUM_PROXIES'] = 1` does the equivalent for DRF's own
  throttles. What remains open is outside this repo: correctness depends on
  the host-level TLS-terminating proxy in front of this container always
  *overwriting* (never appending to, and never passing through a
  client-supplied) `X-Forwarded-For` and `X-Forwarded-Proto` — see the
  host-proxy contract in `docs/remote-mcp-oauth-deploy.md`. Until that's
  confirmed on the host, every client can still bucket together at this
  container's edge.
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
