/* Login page: "Sign in with a passkey" button plus browser autofill
 * (conditional mediation) on the username field. */
(function (window, document) {
  'use strict';
  var P = window.Passkey;
  var box = document.getElementById('passkey-login');
  if (!box || !P || !P.supported) { return; }
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
  // Bumped by stopAutofill() and at the start of every new attempt (a
  // click, or startAutofill's own periodic restart). navigator.credentials
  // calls take real time, and isConditionalMediationAvailable() is itself
  // async with nothing to abort while it's pending -- so a click can land
  // before an in-flight attempt has even created its controller yet. Every
  // async callback below captures `generation` when its own attempt starts
  // and re-checks it before touching controller/timer/the DOM: a mismatch
  // means a newer attempt has already superseded this one (and aborted its
  // controller, if it had one by then), so the callback must be a no-op.
  var generation = 0;

  function finish(result) {
    return P.postJSON('/login/passkey/', {
      challenge_id: result.challenge_id,
      credential: result.credential,
      next: nextInput ? nextInput.value : ''
    }).then(function (data) { window.location.assign(data.redirect); });
  }

  function stopAutofill() {
    generation++;
    window.clearTimeout(timer);
    timer = null;
    if (controller) { controller.abort(); controller = null; }
  }

  function startAutofill() {
    var PKC = window.PublicKeyCredential;
    if (!PKC.isConditionalMediationAvailable) { return; }
    var gen = generation;
    PKC.isConditionalMediationAvailable().then(function (available) {
      if (gen !== generation || !available) { return; }
      var mine = controller = new AbortController();
      // Challenges expire server-side after 5 minutes; refresh just before.
      // Must stop the outstanding conditional request before starting a
      // new one -- calling startAutofill() directly here (as a bare
      // setTimeout callback) left the previous navigator.credentials.get()
      // still pending; the browser rejects the second, still-conditional
      // call that follows, and that rejection lands in errorEl even though
      // nothing the user did caused it (an idle login page would
      // spontaneously show "The passkey request was cancelled." and lose
      // autofill after 4.5 minutes).
      timer = window.setTimeout(function () {
        stopAutofill();
        startAutofill();
      }, 270000);
      P.assertion('conditional', mine.signal).then(finish).catch(function (err) {
        if (gen !== generation || mine.signal.aborted) { return; }
        errorEl.textContent = P.errorMessage(err);
      });
    });
  }

  button.addEventListener('click', function () {
    // Cancel whatever's in flight (autofill, or an earlier click that
    // hasn't settled yet) before starting this attempt, so at most one
    // navigator.credentials.get() call is ever live.
    stopAutofill();
    var gen = generation;
    errorEl.textContent = '';
    button.disabled = true;
    var mine = controller = new AbortController();
    P.assertion(null, mine.signal).then(finish).catch(function (err) {
      // A later click (or the page moving on) already superseded this
      // attempt and cleaned up after it -- leave its button/error state to
      // whichever attempt is current now.
      if (gen !== generation) { return; }
      button.disabled = false;
      // Superseded-by-us aborts are silent; a real NotAllowedError (the
      // user dismissed the browser's own passkey prompt) still reports
      // through P.errorMessage as usual.
      if (!mine.signal.aborted) { errorEl.textContent = P.errorMessage(err); }
      startAutofill();
    });
    // No success handler here: finish() ends in window.location.assign,
    // and the button staying disabled through that navigation is harmless.
  });

  startAutofill();
})(window, document);
