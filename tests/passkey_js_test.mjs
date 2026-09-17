// Unit tests for app/assets/passkey.js -- the WebAuthn helper shared by the
// login, signup, security and recovery pages (see that file's own header
// comment). It has no automated coverage at all (flagged in the Task 17
// review), and the `web` container has no node -- so these run on the HOST
// node instead (v20.18.1 at the time this was written; `node --test` is a
// built-in Node 18+ feature, no test framework or npm dependency needed):
//
//     node --test tests/passkey_js_test.mjs
//
// See tests/README.md for the full "how to run this" writeup, including
// why this can't run in the `web` container.
//
// passkey.js is a plain browser IIFE: `(function (window, document) {
// ...privates... window.Passkey = {...}; })(window, document);` -- only
// `request`/`postJSON`/`create`/`assertion`/`errorMessage`/`supported` are
// exposed on window.Passkey. The functions this file is specifically asked
// to test (b64urlToBuffer, bufferToB64url, credentialToJSON, the
// creationOptions/requestOptions converters) are private closures. Rather
// than either changing the shipped file's public surface just for tests, or
// re-implementing them (which would test the copy, not the real code),
// loadPasskeyModule() below reads the real source text and inserts one
// extra line -- `window.__testHooks = {...}` -- right before the file's own
// closing `})(window, document);`, then runs that (still 100% of the real
// file, unmodified otherwise) in a vm context. The committed passkey.js
// itself is never touched.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..');
const ASSETS_DIR = path.join(REPO_ROOT, 'app', 'assets');
const PASSKEY_JS = path.join(ASSETS_DIR, 'passkey.js');

const CLOSING_CALL = '})(window, document);';
const TEST_HOOKS = `
  window.__testHooks = {
    b64urlToBuffer: b64urlToBuffer,
    bufferToB64url: bufferToB64url,
    credentialToJSON: credentialToJSON,
    creationOptions: creationOptions,
    requestOptions: requestOptions,
    csrfToken: csrfToken
  };
`;

function instrumentedSource() {
  const source = fs.readFileSync(PASSKEY_JS, 'utf8');
  const idx = source.lastIndexOf(CLOSING_CALL);
  assert.notEqual(idx, -1, 'passkey.js no longer ends with ' + JSON.stringify(CLOSING_CALL) +
    ' -- update the test hook injection point in tests/passkey_js_test.mjs to match');
  assert.equal(source.indexOf(CLOSING_CALL), idx, 'expected exactly one IIFE closing call');
  return source.slice(0, idx) + TEST_HOOKS + source.slice(idx);
}

const INSTRUMENTED_SOURCE = instrumentedSource();

/* atob/btoa are Web APIs, not part of the JS language itself, so a vm
 * context (unlike Node's own global scope, which happens to expose them
 * since Node 16) does not have them for free. A first version of these
 * stubs just delegated straight to Buffer.from(value, 'base64') /
 * .toString('base64') -- but Node's base64 decoder is far more forgiving
 * than a real atob: it silently ignores wrong or missing '=' padding
 * instead of throwing, which let a real bug in b64urlToBuffer's own
 * padding arithmetic slip past every test here undetected (caught in
 * review by mutation-testing '==='.slice((base64.length + 3) % 4) into
 * '==='.slice(base64.length % 4) -- every test stayed green even though a
 * real browser would throw InvalidCharacterError on the resulting
 * malformed string for any input whose unpadded length is a multiple of
 * 4). These implement the WHATWG "forgiving-base64 decode" algorithm
 * (https://infra.spec.whatwg.org/#forgiving-base64-decode, as used by
 * atob: https://html.spec.whatwg.org/multipage/webappapis.html#atob)
 * closely enough to reject the same malformed input a real browser would:
 * strip ASCII whitespace, strip trailing '=' padding only when the
 * (whitespace-stripped) length is already a multiple of 4, then throw on
 * a length%4 of 1 or on any character outside the base64 alphabet
 * (a stray '=' included, once padding-stripping didn't apply to it).
 */
function specAtob(value) {
  var data = String(value).replace(/[\t\n\f\r ]/g, '');
  if (data.length % 4 === 0) {
    data = data.replace(/={1,2}$/, '');
  }
  if (data.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(data)) {
    throw new Error('InvalidCharacterError: atob stub -- not correctly encoded base64: ' +
      JSON.stringify(value));
  }
  return Buffer.from(data, 'base64').toString('binary');
}

function specBtoa(value) {
  if (/[^\x00-\xff]/.test(value)) {
    throw new Error('InvalidCharacterError: btoa stub -- character outside \\x00-\\xff: ' +
      JSON.stringify(value));
  }
  return Buffer.from(value, 'binary').toString('base64');
}

/** A fresh vm context with a minimal window/document/navigator, running the
 * real (instrumented) passkey.js in it. `overrides` lets a test control
 * window.PublicKeyCredential, window.i18n, navigator, document, etc.
 * before load -- every test gets its own context, since some of these
 * (e.g. PublicKeyCredential.parseCreationOptionsFromJSON's presence)
 * matter at call time, but starting clean avoids any cross-test leakage
 * regardless.
 */
function loadPasskeyModule(overrides = {}) {
  const documentStub = Object.assign({
    cookie: '',
    querySelector() { return null; },
  }, overrides.document || {});
  const windowStub = Object.assign({
    atob: specAtob,
    btoa: specBtoa,
    PublicKeyCredential: {},
    fetch: () => Promise.reject(new Error('fetch not stubbed for this test')),
    i18n: {},
  }, overrides.window || {});
  const navigatorStub = Object.assign({ credentials: {} }, overrides.navigator || {});
  const sandbox = { window: windowStub, document: documentStub, navigator: navigatorStub };
  const context = vm.createContext(sandbox);
  vm.runInContext(INSTRUMENTED_SOURCE, context, { filename: 'passkey.js' });
  return sandbox;
}

// --- b64urlToBuffer / bufferToB64url -----------------------------------

function toArrayBuffer(bytes) {
  const uint8 = new Uint8Array(bytes);
  return uint8.buffer.slice(uint8.byteOffset, uint8.byteOffset + uint8.byteLength);
}

function assertRoundTrip(hooks, bytes, label) {
  const nodeBuffer = Buffer.from(bytes);
  const expectedEncoded = nodeBuffer.toString('base64url');

  const encoded = hooks.bufferToB64url(toArrayBuffer(bytes));
  assert.equal(encoded, expectedEncoded, label + ': bufferToB64url mismatch vs Buffer.toString(base64url)');
  assert.equal(encoded.includes('+'), false, label + ': base64url output must not contain +');
  assert.equal(encoded.includes('/'), false, label + ': base64url output must not contain /');
  assert.equal(encoded.includes('='), false, label + ': base64url output must not contain padding');

  const decoded = new Uint8Array(hooks.b64urlToBuffer(encoded));
  assert.deepEqual(Array.from(decoded), Array.from(bytes), label + ': b64urlToBuffer round-trip mismatch');
  const expectedDecoded = new Uint8Array(Buffer.from(expectedEncoded, 'base64url'));
  assert.deepEqual(Array.from(decoded), Array.from(expectedDecoded),
    label + ': b64urlToBuffer mismatch vs Buffer.from(base64url)');
}

test('b64urlToBuffer / bufferToB64url round-trip: empty input', () => {
  const { window } = loadPasskeyModule();
  assertRoundTrip(window.__testHooks, [], 'empty');
});

for (const length of [1, 2, 3]) {
  test(`b64urlToBuffer / bufferToB64url round-trip: ${length}-byte input (padding case)`, () => {
    const { window } = loadPasskeyModule();
    const bytes = crypto.randomBytes(length);
    assertRoundTrip(window.__testHooks, bytes, `${length}-byte`);
  });
}

test('b64urlToBuffer / bufferToB64url round-trip: bytes 0x80-0xff', () => {
  const { window } = loadPasskeyModule();
  const bytes = Uint8Array.from({ length: 128 }, (_, i) => 0x80 + i);
  assertRoundTrip(window.__testHooks, bytes, '0x80-0xff');
});

test('b64urlToBuffer / bufferToB64url round-trip: 1 KB of random bytes', () => {
  const { window } = loadPasskeyModule();
  const bytes = crypto.randomBytes(1024);
  assertRoundTrip(window.__testHooks, bytes, '1KB random');
});

test('b64urlToBuffer / bufferToB64url round-trip: a real 32-byte challenge', () => {
  const { window } = loadPasskeyModule();
  const bytes = crypto.randomBytes(32);
  assertRoundTrip(window.__testHooks, bytes, '32-byte challenge');
});

// --- credentialToJSON -----------------------------------------------------
//
// The hardcoded key lists below are checked against py_webauthn's own JSON
// field names, not guessed: webauthn.helpers.structs.RegistrationCredential
// and AuthenticationCredential both have id/raw_id/response/
// authenticator_attachment/type, and their nested
// AuthenticatorAttestationResponse / AuthenticatorAssertionResponse have
// client_data_json/attestation_object/transports and
// client_data_json/authenticator_data/signature/user_handle respectively
// (py_webauthn's own JSON parsing maps the snake_case dataclass fields
// to/from the camelCase wire names asserted here, e.g. raw_id <-> rawId).

test('credentialToJSON: registration credential shape matches what py_webauthn expects', () => {
  const { window } = loadPasskeyModule();
  const credential = {
    id: 'cred-id-b64url',
    rawId: toArrayBuffer([1, 2, 3, 4]),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: toArrayBuffer([10, 11, 12]),
      attestationObject: toArrayBuffer([20, 21, 22]),
      getTransports: () => ['internal', 'hybrid'],
    },
  };
  const out = window.__testHooks.credentialToJSON(credential);

  assert.deepEqual(Object.keys(out).sort(), [
    'authenticatorAttachment', 'clientExtensionResults', 'id', 'rawId', 'response', 'type',
  ].sort());
  assert.deepEqual(Object.keys(out.response).sort(),
    ['attestationObject', 'clientDataJSON', 'transports'].sort());
  assert.equal(out.id, 'cred-id-b64url');
  assert.equal(out.type, 'public-key');
  assert.equal(out.authenticatorAttachment, 'platform');
  assert.deepEqual(out.clientExtensionResults, {});
  assert.equal(out.rawId, Buffer.from([1, 2, 3, 4]).toString('base64url'));
  assert.equal(out.response.clientDataJSON, Buffer.from([10, 11, 12]).toString('base64url'));
  assert.equal(out.response.attestationObject, Buffer.from([20, 21, 22]).toString('base64url'));
  assert.deepEqual(out.response.transports, ['internal', 'hybrid']);
  // A registration response must never carry assertion-only fields.
  assert.equal('authenticatorData' in out.response, false);
  assert.equal('signature' in out.response, false);
  assert.equal('userHandle' in out.response, false);
});

test('credentialToJSON: registration credential without getTransports() -> transports: []', () => {
  const { window } = loadPasskeyModule();
  const credential = {
    id: 'cred-id',
    rawId: toArrayBuffer([1]),
    type: 'public-key',
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: toArrayBuffer([1]),
      attestationObject: toArrayBuffer([2]),
      // no getTransports -- an authenticator/browser that doesn't report it
    },
  };
  const out = window.__testHooks.credentialToJSON(credential);
  // Not assert.deepEqual(out.response.transports, []): the fallback `[]`
  // is constructed by code running *inside* the vm context, so it is an
  // array from that context's own realm -- deepStrictEqual (what
  // node:assert/strict's deepEqual aliases to) compares prototypes too,
  // and a same-shape empty array from a different realm legitimately has
  // a different Array.prototype. A length check is what "-> []" means here.
  assert.equal(out.response.transports.length, 0);
});

test('credentialToJSON: assertion credential shape matches what py_webauthn expects', () => {
  const { window } = loadPasskeyModule();
  const credential = {
    id: 'assert-id',
    rawId: toArrayBuffer([5, 6]),
    type: 'public-key',
    authenticatorAttachment: 'cross-platform',
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: toArrayBuffer([1]),
      authenticatorData: toArrayBuffer([2, 3]),
      signature: toArrayBuffer([4, 5, 6]),
      userHandle: toArrayBuffer([7, 8]),
    },
  };
  const out = window.__testHooks.credentialToJSON(credential);

  assert.deepEqual(Object.keys(out.response).sort(),
    ['authenticatorData', 'clientDataJSON', 'signature', 'userHandle'].sort());
  assert.equal(out.response.authenticatorData, Buffer.from([2, 3]).toString('base64url'));
  assert.equal(out.response.signature, Buffer.from([4, 5, 6]).toString('base64url'));
  assert.equal(out.response.userHandle, Buffer.from([7, 8]).toString('base64url'));
  // An assertion response must never carry registration-only fields.
  assert.equal('attestationObject' in out.response, false);
  assert.equal('transports' in out.response, false);
});

test('credentialToJSON: assertion credential with no userHandle omits the field entirely', () => {
  const { window } = loadPasskeyModule();
  const credential = {
    id: 'assert-id-no-handle',
    rawId: toArrayBuffer([1]),
    type: 'public-key',
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: toArrayBuffer([1]),
      authenticatorData: toArrayBuffer([2]),
      signature: toArrayBuffer([3]),
      // no userHandle -- e.g. a non-resident-key credential
    },
  };
  const out = window.__testHooks.credentialToJSON(credential);
  assert.equal('userHandle' in out.response, false);
});

test('credentialToJSON: prefers credential.toJSON() when present, ignoring everything else', () => {
  const { window } = loadPasskeyModule();
  const sentinel = { thisIsTheShortcutResult: true };
  const credential = {
    id: 'ignored',
    rawId: toArrayBuffer([9, 9, 9]),
    type: 'public-key',
    getClientExtensionResults() { throw new Error('must not be called when toJSON() is present'); },
    response: { clientDataJSON: toArrayBuffer([1]) },
    toJSON: () => sentinel,
  };
  const out = window.__testHooks.credentialToJSON(credential);
  assert.equal(out, sentinel);
});

// --- creationOptions / requestOptions converters ---------------------------

function b64url(bytes) { return Buffer.from(bytes).toString('base64url'); }

test('creationOptions: delegates to PublicKeyCredential.parseCreationOptionsFromJSON when present', () => {
  const sentinel = { parsed: true };
  const { window } = loadPasskeyModule({
    window: { PublicKeyCredential: { parseCreationOptionsFromJSON: (json) => sentinel } },
  });
  const result = window.__testHooks.creationOptions({ challenge: b64url([1]), user: { id: b64url([2]) } });
  assert.equal(result, sentinel);
});

test('creationOptions: manual fallback decodes challenge/user.id/excludeCredentials without the parser', () => {
  const { window } = loadPasskeyModule({ window: { PublicKeyCredential: {} } });
  const json = {
    rp: { id: 'example.com', name: 'Example' },
    user: { id: b64url([1, 2, 3]), name: 'alice', displayName: 'Alice' },
    challenge: b64url([9, 9, 9]),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [{ id: b64url([4, 5]), type: 'public-key', transports: ['internal'] }],
  };
  const out = window.__testHooks.creationOptions(json);

  assert.deepEqual(new Uint8Array(out.challenge), new Uint8Array([9, 9, 9]));
  assert.deepEqual(new Uint8Array(out.user.id), new Uint8Array([1, 2, 3]));
  assert.equal(out.user.name, 'alice');
  assert.equal(out.user.displayName, 'Alice');
  assert.equal(out.rp.id, 'example.com');
  assert.deepEqual(out.pubKeyCredParams, [{ type: 'public-key', alg: -7 }]);
  assert.equal(out.excludeCredentials.length, 1);
  assert.deepEqual(new Uint8Array(out.excludeCredentials[0].id), new Uint8Array([4, 5]));
  assert.equal(out.excludeCredentials[0].type, 'public-key');
  assert.deepEqual(out.excludeCredentials[0].transports, ['internal']);
});

test('creationOptions: manual fallback with no excludeCredentials -> []', () => {
  const { window } = loadPasskeyModule({ window: { PublicKeyCredential: {} } });
  const out = window.__testHooks.creationOptions({
    user: { id: b64url([1]) }, challenge: b64url([2]),
  });
  // See the transports-fallback test above for why this is a length check,
  // not assert.deepEqual against a host-realm [] literal.
  assert.equal(out.excludeCredentials.length, 0);
});

test('requestOptions: delegates to PublicKeyCredential.parseRequestOptionsFromJSON when present', () => {
  const sentinel = { parsed: true };
  const { window } = loadPasskeyModule({
    window: { PublicKeyCredential: { parseRequestOptionsFromJSON: (json) => sentinel } },
  });
  const result = window.__testHooks.requestOptions({ challenge: b64url([1]) });
  assert.equal(result, sentinel);
});

test('requestOptions: manual fallback decodes challenge/allowCredentials without the parser', () => {
  const { window } = loadPasskeyModule({ window: { PublicKeyCredential: {} } });
  const json = {
    rpId: 'example.com',
    challenge: b64url([7, 7, 7]),
    allowCredentials: [{ id: b64url([8, 8]), type: 'public-key' }],
  };
  const out = window.__testHooks.requestOptions(json);

  assert.deepEqual(new Uint8Array(out.challenge), new Uint8Array([7, 7, 7]));
  assert.equal(out.rpId, 'example.com');
  assert.equal(out.allowCredentials.length, 1);
  assert.deepEqual(new Uint8Array(out.allowCredentials[0].id), new Uint8Array([8, 8]));
});

test('requestOptions: manual fallback with no allowCredentials -> []', () => {
  const { window } = loadPasskeyModule({ window: { PublicKeyCredential: {} } });
  const out = window.__testHooks.requestOptions({ challenge: b64url([1]) });
  // See the transports-fallback test above for why this is a length check,
  // not assert.deepEqual against a host-realm [] literal.
  assert.equal(out.allowCredentials.length, 0);
});

// --- csrfToken --------------------------------------------------------
//
// csrfToken() is a security control (it's what gets sent back as
// X-CSRFToken on every state-changing request this file makes -- see
// request()), and its documented ordering -- the rendered
// csrfmiddlewaretoken hidden input first, the (non-HttpOnly, per
// settings.py) csrftoken cookie only as a fallback -- is exactly the kind
// of thing a refactor could quietly invert without any visible symptom
// on a page that always has both anyway.

test('csrfToken: prefers the rendered csrfmiddlewaretoken input when present', () => {
  const { window } = loadPasskeyModule({
    document: {
      cookie: 'csrftoken=cookie-value',
      querySelector: (selector) =>
        selector === 'input[name=csrfmiddlewaretoken]' ? { value: 'input-value' } : null,
    },
  });
  assert.equal(window.__testHooks.csrfToken(), 'input-value');
});

test('csrfToken: falls back to the csrftoken cookie when no such input exists', () => {
  const { window } = loadPasskeyModule({
    document: { cookie: 'csrftoken=cookie-value', querySelector: () => null },
  });
  assert.equal(window.__testHooks.csrfToken(), 'cookie-value');
});

test('csrfToken: falls back to the cookie when the input exists but is empty', () => {
  const { window } = loadPasskeyModule({
    document: {
      cookie: 'csrftoken=cookie-value',
      querySelector: (selector) =>
        selector === 'input[name=csrfmiddlewaretoken]' ? { value: '' } : null,
    },
  });
  assert.equal(window.__testHooks.csrfToken(), 'cookie-value');
});

test('csrfToken: reads the csrftoken cookie out of a multi-cookie document.cookie string', () => {
  const { window } = loadPasskeyModule({
    document: {
      cookie: 'django_language=th; csrftoken=cookie-value; sessionid=abc123',
      querySelector: () => null,
    },
  });
  assert.equal(window.__testHooks.csrfToken(), 'cookie-value');
});

// --- errorMessage -----------------------------------------------------

const I18N = {
  passkeyCancelled: 'You cancelled the passkey prompt.',
  passkeyRateLimited: 'Too many attempts, please wait a moment.',
  passkeyRateLimitedWait: 'Too many attempts, please wait {seconds}s.',
  signupGenericError: 'Something went wrong.',
};

function passkeyWithI18n() {
  return loadPasskeyModule({ window: { i18n: I18N } });
}

test('errorMessage: {detail: ...} body', () => {
  const { window } = passkeyWithI18n();
  const err = { status: 400, data: { detail: 'Passkey registration failed.' } };
  assert.equal(window.Passkey.errorMessage(err), 'Passkey registration failed.');
});

test('errorMessage: DRF field-error map picks the first field\'s first message', () => {
  const { window } = passkeyWithI18n();
  const err = { status: 400, data: { username: ['A user with that username already exists.'] } };
  assert.equal(window.Passkey.errorMessage(err), 'A user with that username already exists.');
});

test('errorMessage: {} body falls back to the generic message', () => {
  const { window } = passkeyWithI18n();
  assert.equal(window.Passkey.errorMessage({ status: 400, data: {} }), I18N.signupGenericError);
});

test('errorMessage: null body falls back to the generic message', () => {
  const { window } = passkeyWithI18n();
  assert.equal(window.Passkey.errorMessage({ status: 400, data: null }), I18N.signupGenericError);
});

test('errorMessage: a list body is never mistaken for a field-error map', () => {
  const { window } = passkeyWithI18n();
  const err = { status: 400, data: ['not a field-error map'] };
  assert.equal(window.Passkey.errorMessage(err), I18N.signupGenericError);
});

test('errorMessage: NotAllowedError (user dismissed the browser prompt)', () => {
  const { window } = passkeyWithI18n();
  const err = { name: 'NotAllowedError' };
  assert.equal(window.Passkey.errorMessage(err), I18N.passkeyCancelled);
});

test('errorMessage: nginx 429 shape ({error, retry_after, detail}) substitutes {seconds}', () => {
  const { window } = passkeyWithI18n();
  const err = { status: 429, data: { error: 'rate_limited', retry_after: 30, detail: 'ignored' } };
  assert.equal(window.Passkey.errorMessage(err), 'Too many attempts, please wait 30s.');
});

test('errorMessage: DRF 429 shape ({detail}, no retry_after) uses the generic rate-limit message', () => {
  const { window } = passkeyWithI18n();
  // DRF's PasskeyRateThrottle body: no retry_after key at all. The 429
  // branch must win over the generic data.detail handling below it -- this
  // is the one case that proves that ordering, since this body *does* have
  // a 'detail' string that a naive implementation could return instead.
  const err = { status: 429, data: { detail: 'Request was throttled. Expected available in 38 seconds.' } };
  assert.equal(window.Passkey.errorMessage(err), I18N.passkeyRateLimited);
});

// --- node --check cleanliness for every passkey*.js / account_security.js -

test('node --check: every app/assets/passkey*.js and account_security.js file parses cleanly', () => {
  const candidates = fs.readdirSync(ASSETS_DIR)
    .filter((name) => (name.startsWith('passkey') || name === 'account_security.js') && name.endsWith('.js'))
    .sort();
  assert.ok(candidates.length >= 5, 'expected to find at least the 5 known passkey/security JS files, found: ' +
    candidates.join(', '));
  for (const name of candidates) {
    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ['--check', path.join(ASSETS_DIR, name)], { stdio: 'pipe' });
    }, `node --check failed for app/assets/${name}`);
  }
});
