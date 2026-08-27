// The whole of this app's JavaScript: copy a credential that is on screen once.
//
// It is loaded only by the two pages that can show one - the renderer emits the <script> beside the
// buttons rather than the shell emitting it on every page - so the other six are still the
// zero-JavaScript pages the policy header describes. Same-origin file, which `default-src 'self'`
// already covers: nothing inline, and no change to the CSP.
//
// Delegated from the document rather than bound per button, because a page may carry two of them
// and this file is included once per card. Everything it needs is on the button: `data-copy` is the
// id of the element holding the value, and `data-copied` is what to say afterwards - a sentence,
// which is why it comes from the text table and not from here.
//
// The button does nothing this page could not do without it. The value sits in a `<code>` the
// stylesheet marks `user-select: all`, so one click selects the whole credential; this saves a
// keystroke rather than being the only way through, which is what makes it acceptable to add a
// script to an app that had none.
(function () {
  'use strict';

  // Restored rather than left saying "Copied", so a second copy after editing something else does
  // not look like it did nothing. Long enough to read, short enough that the button is back to
  // being a button before anybody presses it again.
  var RESTORE_MS = 1600;

  document.addEventListener('click', function (event) {
    var button = event.target.closest ? event.target.closest('button.copy') : null;

    if (!button) {
      return;
    }

    var source = document.getElementById(button.getAttribute('data-copy'));

    if (!source) {
      return;
    }

    // navigator.clipboard is unavailable on an insecure origin, and this app is served over TLS in
    // any deployment that has an authorization server to talk to. Where it is missing - a plain
    // http:// development host - the selection below is the whole behaviour, which is the same
    // thing that happens with this file absent.
    var text = source.textContent;

    if (!navigator.clipboard) {
      select(source);
      return;
    }

    navigator.clipboard.writeText(text).then(function () {
      said(button);
    }, function () {
      // Refused - a permissions policy, or a window that was not focused. Selecting is the honest
      // fallback: it leaves the operator one keystroke from the same result rather than a button
      // that reports success it did not have.
      select(source);
    });
  });

  function said(button) {
    var was = button.textContent;
    var now = button.getAttribute('data-copied');

    if (!now || button.dataset.restoring) {
      return;
    }

    button.dataset.restoring = '1';
    button.textContent = now;

    setTimeout(function () {
      button.textContent = was;
      delete button.dataset.restoring;
    }, RESTORE_MS);
  }

  function select(element) {
    var range = document.createRange();
    range.selectNodeContents(element);

    var selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
})();
