/* Password-reset confirm page: recover by creating a new passkey. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-recover');
  if (!box || !P || !P.supported) { return; }
  box.hidden = false;

  var button = document.getElementById('passkey-recover-button');
  var errorEl = document.getElementById('passkey-recover-error');
  var uid = {uidb64: box.dataset.uidb64};

  // Bumped at the start of every click. The button is disabled for the
  // duration of a ceremony (see below), so in the normal case there is
  // never a second click in flight to supersede this one -- but a stray
  // re-entrant click (e.g. Enter fired twice before disabled takes effect)
  // must not let an older ceremony's response clobber a newer attempt's
  // button/error state. Same pattern as passkey_login.js's and
  // passkey_signup.js's own `generation`.
  var generation = 0;

  button.addEventListener('click', function () {
    if (button.disabled) { return; }
    generation++;
    var gen = generation;
    errorEl.textContent = '';
    button.disabled = true;
    P.create('/account/recover/passkey/begin/', '/account/recover/passkey/finish/', uid, uid)
      .then(function (data) {
        if (gen !== generation) { return; }
        window.location.assign(data.redirect);
      })
      .catch(function (err) {
        if (gen !== generation) { return; }
        button.disabled = false;
        errorEl.textContent = P.errorMessage(err);
      });
    // No success handler re-enables the button: finish() ends in
    // window.location.assign, and staying disabled through that navigation
    // is harmless (same rationale as passkey_login.js/passkey_signup.js).
  });
})(window, document);
