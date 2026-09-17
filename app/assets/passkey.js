/* Passkey (WebAuthn) helpers shared by the login, signup, security and
 * recovery pages. Vanilla JS on purpose: base.html boots AngularJS, and
 * nothing here may be interpolated by it -- this file never builds HTML
 * from server-provided or user-provided text (no innerHTML/insertAdjacentHTML
 * of untrusted strings); any page that shows such text must set it with
 * textContent and, since AngularJS is bootstrapped on every page, mark the
 * containing element ng-non-bindable so Angular's own interpolation never
 * touches it either (see base.html's existing ng-non-bindable usages).
 *
 * CSRF: csrfToken() reads the csrfmiddlewaretoken hidden input first, so
 * every page that calls into this helper (login, signup, account/security,
 * recovery -- Tasks 18-21) MUST render {% csrf_token %} somewhere in its
 * form. It falls back to the csrftoken cookie (not HttpOnly in this
 * project -- see settings.py) for a page that only ever calls this helper
 * from script and never renders a form of its own.
 */
(function (window, document) {
  'use strict';

  function b64urlToBuffer(value) {
    var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    var binary = window.atob(base64 + '==='.slice((base64.length + 3) % 4));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function withIds(list) {
    return (list || []).map(function (item) {
      return Object.assign({}, item, {id: b64urlToBuffer(item.id)});
    });
  }

  function creationOptions(json) {
    if (window.PublicKeyCredential.parseCreationOptionsFromJSON) {
      return window.PublicKeyCredential.parseCreationOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
      challenge: b64urlToBuffer(json.challenge),
      user: Object.assign({}, json.user, {id: b64urlToBuffer(json.user.id)}),
      excludeCredentials: withIds(json.excludeCredentials)
    });
  }

  function requestOptions(json) {
    if (window.PublicKeyCredential.parseRequestOptionsFromJSON) {
      return window.PublicKeyCredential.parseRequestOptionsFromJSON(json);
    }
    return Object.assign({}, json, {
      challenge: b64urlToBuffer(json.challenge),
      allowCredentials: withIds(json.allowCredentials)
    });
  }

  function credentialToJSON(credential) {
    if (typeof credential.toJSON === 'function') { return credential.toJSON(); }
    var response = credential.response;
    var out = {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {clientDataJSON: bufferToB64url(response.clientDataJSON)}
    };
    if (response.attestationObject) {
      out.response.attestationObject = bufferToB64url(response.attestationObject);
      out.response.transports = response.getTransports ? response.getTransports() : [];
    } else {
      out.response.authenticatorData = bufferToB64url(response.authenticatorData);
      out.response.signature = bufferToB64url(response.signature);
      if (response.userHandle) { out.response.userHandle = bufferToB64url(response.userHandle); }
    }
    return out;
  }

  function cookie(name) {
    var prefix = name + '=';
    var parts = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].indexOf(prefix) === 0) {
        return decodeURIComponent(parts[i].slice(prefix.length));
      }
    }
    return '';
  }

  function csrfToken() {
    var input = document.querySelector('input[name=csrfmiddlewaretoken]');
    if (input && input.value) { return input.value; }
    return cookie('csrftoken');
  }

  function request(method, url, body) {
    var init = {method: method, credentials: 'same-origin',
                headers: {'Accept': 'application/json', 'X-CSRFToken': csrfToken()}};
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return window.fetch(url, init).then(function (resp) {
      return resp.text().then(function (text) {
        var data = {};
        try { data = text ? JSON.parse(text) : {}; } catch (e) { data = {}; }
        if (!resp.ok) {
          var err = new Error('HTTP ' + resp.status);
          err.status = resp.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function postJSON(url, body) { return request('POST', url, body || {}); }

  /* begin -> navigator.credentials.create -> finish; resolves with finish's JSON. */
  function create(beginUrl, finishUrl, beginBody, finishExtra) {
    return postJSON(beginUrl, beginBody).then(function (begin) {
      return navigator.credentials.create({publicKey: creationOptions(begin.options)})
        .then(function (credential) {
          return postJSON(finishUrl, Object.assign({
            challenge_id: begin.challenge_id,
            credential: credentialToJSON(credential)
          }, finishExtra || {}));
        });
    });
  }

  /* Login challenge + navigator.credentials.get; resolves with {challenge_id, credential}. */
  function assertion(mediation, signal) {
    return postJSON('/api/passkeys/login/begin/').then(function (begin) {
      var args = {publicKey: requestOptions(begin.options)};
      if (mediation) { args.mediation = mediation; }
      if (signal) { args.signal = signal; }
      return navigator.credentials.get(args).then(function (credential) {
        return {challenge_id: begin.challenge_id, credential: credentialToJSON(credential)};
      });
    });
  }

  /* err.data is the parsed JSON error body (see request() above), which is
   * either {} (no/unparseable body), {'detail': '...'} or a DRF field-error
   * map like {'name': ['...']} / {'non_field_errors': ['...']} -- never
   * assume either shape without checking, since a caller passing a non-JSON
   * or empty body reaches this with err.data == {}.
   *
   * status 429 is special-cased ahead of that generic handling so both
   * sources of a passkey 429 read the same friendly way: nginx's own rate
   * limit (nginx.conf's @ratelimited_passkey/@ratelimited_passkey_manage,
   * body {'error':..., 'retry_after':..., 'detail':...}) and DRF's
   * PasskeyRateThrottle (body {'detail': 'Request was throttled. ...'}, no
   * retry_after key) -- using retry_after when nginx supplied it, and a
   * generic wait-a-moment message when it didn't, rather than falling
   * through to whatever 'detail' string happens to be on the response. */
  function errorMessage(err) {
    if (err && err.name === 'NotAllowedError') { return window.i18n.passkeyCancelled; }
    var data = err && err.data;
    if (err && err.status === 429) {
      var retryAfter = data && data.retry_after;
      return retryAfter
        ? window.i18n.passkeyRateLimitedWait.replace('{seconds}', retryAfter)
        : window.i18n.passkeyRateLimited;
    }
    if (data && typeof data === 'object') {
      if (data.detail) { return String(data.detail); }
      var keys = Object.keys(data);
      if (keys.length && Array.isArray(data[keys[0]]) && data[keys[0]].length) {
        return String(data[keys[0]][0]);
      }
    }
    return window.i18n.signupGenericError;
  }

  window.Passkey = {
    supported: !!(window.PublicKeyCredential && navigator.credentials && window.fetch),
    request: request,
    postJSON: postJSON,
    create: create,
    assertion: assertion,
    errorMessage: errorMessage
  };
})(window, document);
