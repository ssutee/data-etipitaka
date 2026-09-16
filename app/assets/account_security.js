/* Account security page: list, add (after step-up), rename and delete
 * passkeys; remove the password once a passkey exists.
 *
 * All five account endpoints (list, register begin/finish, rename, delete,
 * password remove) share ONE per-user throttle bucket (20/min -- see
 * PasskeyRateThrottle in user_data/passkey_views.py). Re-fetching the list
 * after every mutation would burn 2-4 requests per change, so instead each
 * mutation's own response updates local `state` directly and load() runs
 * only once, on page open (see updateFromRename/removeLocally/
 * insertPasskey/setHasPassword below).
 */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var root = document.getElementById('security');
  if (!root) { return; }
  var t = root.dataset;  // translated strings rendered by Django
  var rows = document.getElementById('passkey-rows');
  var errorEl = document.getElementById('security-error');
  var state = {has_password: false, passkeys: []};

  function $(id) { return document.getElementById(id); }

  function fail(err) { errorEl.textContent = P.errorMessage(err); }

  function formatDate(value) { return value ? new Date(value).toLocaleString() : t.never; }

  function cell(text) {
    var td = document.createElement('td');
    td.textContent = text;
    return td;
  }

  function actionButton(label, cls, onClick) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-xs ' + cls;
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  function render() {
    rows.textContent = '';
    state.passkeys.forEach(function (passkey) {
      var tr = document.createElement('tr');
      var kind = passkey.backed_up ? t.synced : t.deviceBound;
      tr.appendChild(cell(passkey.name));
      tr.appendChild(cell(passkey.authenticator ? passkey.authenticator + ' · ' + kind : kind));
      tr.appendChild(cell(formatDate(passkey.created_at)));
      tr.appendChild(cell(formatDate(passkey.last_used_at)));
      var actions = document.createElement('td');
      actions.appendChild(actionButton(t.rename, 'btn-default', function () { rename(passkey); }));
      actions.appendChild(document.createTextNode(' '));
      actions.appendChild(actionButton(t.remove, 'btn-danger', function () { remove(passkey); }));
      tr.appendChild(actions);
      rows.appendChild(tr);
    });
    $('passkey-empty').hidden = state.passkeys.length > 0;
    $('passkey-unsupported').hidden = P.supported;
    $('add-passkey').hidden = !P.supported;
    $('step-up-password').hidden = !state.has_password;
    $('password-status').textContent = state.has_password ? t.hasPassword : t.noPassword;
    $('remove-password').hidden = !(state.has_password && state.passkeys.length > 0);
    setActionsDisabled(busy);
  }

  // --- local state updates (no re-fetch after a mutation) -----------------

  function passkeySortKey(passkey) {
    // created_at then id, matching passkey_manage.list_passkeys's own
    // `.order_by('created_at', 'pk')` -- Date parses the isoformat()
    // string the server sends, so this survives sub-second ties the same
    // way the DB's own tiebreak (id) does.
    return [new Date(passkey.created_at).getTime(), passkey.id];
  }

  function comparePasskeys(a, b) {
    var ka = passkeySortKey(a);
    var kb = passkeySortKey(b);
    if (ka[0] !== kb[0]) { return ka[0] - kb[0]; }
    return ka[1] - kb[1];
  }

  function insertPasskey(passkey) {
    state.passkeys.push(passkey);
    state.passkeys.sort(comparePasskeys);
  }

  function replacePasskey(passkey) {
    for (var i = 0; i < state.passkeys.length; i++) {
      if (state.passkeys[i].id === passkey.id) {
        state.passkeys[i] = passkey;
        return;
      }
    }
    // Not found locally (shouldn't happen for a rename of a row we just
    // rendered) -- fall back to inserting it so the UI still reflects the
    // server's own state rather than silently dropping the change.
    insertPasskey(passkey);
  }

  function removeLocally(id) {
    state.passkeys = state.passkeys.filter(function (p) { return p.id !== id; });
  }

  // --- in-flight guard ------------------------------------------------------
  // One page-wide `busy` flag/generation counter, not a per-button one:
  // add-passkey, rename and delete all read and write the same shared
  // `state.passkeys` array, and add-passkey's step-up can itself involve a
  // real WebAuthn prompt that takes user-scale time -- so overlapping
  // mutations are serialized, the same way passkey_login.js and
  // passkey_signup.js serialize their own single in-flight ceremony.
  var busy = false;
  var generation = 0;

  function setActionsDisabled(disabled) {
    $('add-passkey-button').disabled = disabled;
    $('remove-password-button').disabled = disabled;
    var buttons = rows.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) { buttons[i].disabled = disabled; }
  }

  function beginAction() {
    if (busy) { return null; }
    busy = true;
    generation++;
    setActionsDisabled(true);
    return generation;
  }

  // Success path: render() below already calls setActionsDisabled(busy),
  // so clear `busy` before it runs.
  function endAction(gen) {
    if (gen !== generation) { return false; }
    busy = false;
    return true;
  }

  // Failure path: only re-enable if this is still the current attempt --
  // a superseded continuation (shouldn't happen while busy blocks new
  // attempts, but mirrors the defensive check in passkey_login.js/
  // passkey_signup.js) must not clobber a newer attempt's button state.
  function failAction(gen, err) {
    if (gen !== generation) { return; }
    busy = false;
    setActionsDisabled(false);
    fail(err);
  }

  function load() {
    return P.request('GET', '/api/passkeys/').then(function (data) {
      state = data;
      render();
    }).catch(fail);
  }

  function rename(passkey) {
    var name = window.prompt(t.renamePrompt, passkey.name);
    if (name === null) { return; }
    var gen = beginAction();
    if (gen === null) { return; }
    errorEl.textContent = '';
    P.request('PATCH', '/api/passkeys/' + passkey.id + '/', {name: name}).then(function (updated) {
      if (!endAction(gen)) { return; }
      replacePasskey(updated);
      render();
    }).catch(function (err) { failAction(gen, err); });
  }

  function remove(passkey) {
    if (!window.confirm(window.i18n.confirmDelete)) { return; }
    var gen = beginAction();
    if (gen === null) { return; }
    errorEl.textContent = '';
    P.request('DELETE', '/api/passkeys/' + passkey.id + '/').then(function () {
      if (!endAction(gen)) { return; }
      removeLocally(passkey.id);
      render();
    }).catch(function (err) { failAction(gen, err); });
  }

  function stepUp() {
    if (state.has_password) {
      return Promise.resolve({password: $('step-up-password-input').value});
    }
    return P.assertion(null, null).then(function (proof) { return {step_up: proof}; });
  }

  $('add-passkey-button').addEventListener('click', function () {
    var gen = beginAction();
    if (gen === null) { return; }
    errorEl.textContent = '';
    stepUp().then(function (proof) {
      return P.create('/api/passkeys/register/begin/', '/api/passkeys/register/finish/', proof);
    }).then(function (passkey) {
      if (!endAction(gen)) { return; }
      $('step-up-password-input').value = '';
      insertPasskey(passkey);
      render();
    }).catch(function (err) {
      $('step-up-password-input').value = '';
      failAction(gen, err);
    });
  });

  $('remove-password-button').addEventListener('click', function () {
    var gen = beginAction();
    if (gen === null) { return; }
    errorEl.textContent = '';
    var input = $('remove-password-input');
    P.postJSON('/api/passkeys/password/remove/', {password: input.value}).then(function (data) {
      if (!endAction(gen)) { return; }
      input.value = '';
      state.has_password = data.has_password;
      render();
    }).catch(function (err) {
      input.value = '';
      failAction(gen, err);
    });
  });

  load();
})(window, document);
