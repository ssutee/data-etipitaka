/* Login page: "Sign in with a passkey" button plus browser autofill
 * (conditional mediation) on the username field. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-login');
  if (!box || !P.supported) { return; }
  box.hidden = false;

  var button = document.getElementById('passkey-login-button');
  var errorEl = document.getElementById('passkey-login-error');
  // base.html's language-switcher form also has a hidden input[name=next]
  // (always present, holding request.path); scope to the login form
  // (id="signup") so this finds the *real* redirect target instead of that
  // unrelated field, which is always the first input[name=next] on the page.
  var nextInput = document.querySelector('#signup input[name=next]');
  var controller = null;
  var timer = null;

  function finish(result) {
    return P.postJSON('/login/passkey/', {
      challenge_id: result.challenge_id,
      credential: result.credential,
      next: nextInput ? nextInput.value : ''
    }).then(function (data) { window.location.assign(data.redirect); });
  }

  function stopAutofill() {
    window.clearTimeout(timer);
    if (controller) { controller.abort(); controller = null; }
  }

  function startAutofill() {
    var PKC = window.PublicKeyCredential;
    if (!PKC.isConditionalMediationAvailable) { return; }
    PKC.isConditionalMediationAvailable().then(function (available) {
      if (!available) { return; }
      stopAutofill();
      var mine = controller = new AbortController();
      // Challenges expire server-side after 5 minutes; refresh just before.
      timer = window.setTimeout(startAutofill, 270000);
      P.assertion('conditional', mine.signal).then(finish).catch(function (err) {
        if (mine.signal.aborted) { return; }
        errorEl.textContent = P.errorMessage(err);
      });
    });
  }

  button.addEventListener('click', function () {
    errorEl.textContent = '';
    stopAutofill();
    P.assertion(null, null).then(finish).catch(function (err) {
      errorEl.textContent = P.errorMessage(err);
      startAutofill();
    });
  });

  startAutofill();
})(window, document);
