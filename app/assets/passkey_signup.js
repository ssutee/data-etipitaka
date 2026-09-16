/* Signup page: passkey signup by default, the password form as a fallback. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-signup');
  var passwordBox = document.getElementById('password-signup');
  if (!box || !passwordBox || !P || !P.supported) { return; }
  box.hidden = false;
  passwordBox.hidden = true;

  var form = document.getElementById('passkey-signup-form');
  var button = form.querySelector('button[type="submit"]');
  var errorEl = document.getElementById('passkey-signup-error');
  var emailErrorEl = document.getElementById('passkey-email-error');
  var usernameErrorEl = document.getElementById('passkey-username-error');

  document.getElementById('show-password-signup').addEventListener('click', function (event) {
    event.preventDefault();
    box.hidden = true;
    passwordBox.hidden = false;
  });

  // Bumped at the start of every submit. The submit button is disabled for
  // the duration of a ceremony (see below), so in the normal case there is
  // never a second submit in flight to supersede this one -- but a stray
  // re-entrant submit (e.g. Enter fired twice before disabled takes effect)
  // must not let an older ceremony's response clobber a newer attempt's
  // button/error state. Same pattern as passkey_login.js's `generation`.
  var generation = 0;

  function clearErrors() {
    errorEl.textContent = '';
    emailErrorEl.textContent = '';
    usernameErrorEl.textContent = '';
  }

  // begin_signup/finish_signup report SignupInvalid.errors as a DRF field
  // map, e.g. {'username': [...], 'email': [...]} -- a simultaneously taken
  // username and email both come back at once, so both must be shown next
  // to their own inputs instead of picking just the first key. Anything
  // else (a cancelled ceremony, an empty body, {'detail': ...}) falls back
  // to the generic message.
  function showErrors(err) {
    clearErrors();
    var data = err && err.data;
    if (data && typeof data === 'object' && (data.email || data.username)) {
      if (data.email && data.email.length) { emailErrorEl.textContent = String(data.email[0]); }
      if (data.username && data.username.length) { usernameErrorEl.textContent = String(data.username[0]); }
      return;
    }
    errorEl.textContent = P.errorMessage(err);
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (button.disabled) { return; }
    generation++;
    var gen = generation;
    clearErrors();
    button.disabled = true;
    P.create('/api/passkeys/signup/begin/', '/api/passkeys/signup/finish/', {
      username: document.getElementById('passkey-username').value,
      email: document.getElementById('passkey-email').value
    }).then(function () {
      if (gen !== generation) { return; }
      window.location.assign('/signup/validate/');
    }).catch(function (err) {
      if (gen !== generation) { return; }
      button.disabled = false;
      showErrors(err);
    });
    // No success handler re-enables the button: finish() ends in
    // window.location.assign, and staying disabled through that navigation
    // is harmless (same rationale as passkey_login.js).
  });
})(window, document);
