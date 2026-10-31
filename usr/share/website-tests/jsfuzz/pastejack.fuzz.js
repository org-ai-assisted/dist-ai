'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for secure-terminal's attacks/pastejack.js -- the clipboard "pastejack"
   demo. The demo deliberately COPIES a hidden-payload string (two echo halves joined by a
   zero-width space) and REVEALS the exact same bytes with the zero-width space made visible. The
   security-relevant invariants: (1) what reaches navigator.clipboard is EXACTLY the demo payload
   -- the two echo halves plus exactly two zero-width separators, nothing more hidden; (2) the
   revealed text is written to a SAFE sink -- out.textContent only, so no element/markup is ever
   injected, and the on-screen text contains NO raw zero-width character (every one is rendered as
   the literal marker '<U+200B>'), so nothing invisible escapes into the DOM. Curated DOM configs
   drive every branch to deterministic 100% c8. */

const { fc, test, sitePath } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'attacks/pastejack.js');
const Z = String.fromCharCode(0x200b);   /* zero-width space (ASCII-only source) */
const DOM = '<button id="pd-copy">c</button><button id="pd-reveal">r</button>'
          + '<div id="pd-status"></div><div id="pd-out" hidden></div>';
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

/* --- coverage: every branch, deterministic (mirrors the jscov DOM configs) --- */

test('pastejack: missing elements -> early return', function () {
  loadScript(JS, '<div></div>', {});    // !copy -> return
});

test('pastejack: reveal shows payload with visible <U+200B> markers', function () {
  const r = loadScript(JS, DOM, {});
  r.win.document.getElementById('pd-reveal').click();
  const out = r.win.document.getElementById('pd-out');
  if (out.hidden !== false) { throw new Error('reveal did not unhide output'); }
  if (out.textContent.indexOf('<U+200B>') < 0) { throw new Error('zero-width not rendered as marker'); }
  if (r.win.document.getElementById('pd-status').textContent.indexOf('Revealed') < 0) { throw new Error('status not set'); }
});

test('pastejack: copy with clipboard resolve -> status Copied', async function () {
  const r = loadScript(JS, DOM, {});
  r.win.document.getElementById('pd-copy').click();
  await tick();
  if (r.copied.length !== 1) { throw new Error('clipboard not written once'); }
  if (r.win.document.getElementById('pd-status').textContent.indexOf('Copied') < 0) { throw new Error('resolve status wrong'); }
});

test('pastejack: copy with clipboard reject -> shows payload', async function () {
  const r = loadScript(JS, DOM, {
    setup: function (w) { w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); }; },
  });
  r.win.document.getElementById('pd-copy').click();
  await tick();
  if (r.win.document.getElementById('pd-out').hidden !== false) { throw new Error('reject did not reveal payload'); }
});

test('pastejack: copy without clipboard -> else branch shows payload', function () {
  const r = loadScript(JS, DOM, { clipboard: false });
  r.win.document.getElementById('pd-copy').click();
  if (r.win.document.getElementById('pd-out').hidden !== false) { throw new Error('no-clipboard did not reveal payload'); }
});

/* --- invariants --- */

/* For ANY ordering of reveal/copy clicks and with or without a clipboard API, the output sink
   stays SAFE and the clipboard payload stays EXACTLY the demo payload:
     - out holds only text (no injected element) -> querySelectorAll('*') empty;
     - the rendered text never contains a raw zero-width char (all shown as the marker);
     - every clipboard write is the two-echo payload with exactly two zero-width separators;
     - when both revealed and copied, the shown text is byte-for-byte the clipboard payload with
       each zero-width char replaced by the visible marker (the demo's "exactly what Copy puts on
       your clipboard" promise).
   The harness records clipboard writes synchronously, so no await is needed here. */
test('pastejack: safe text sink, no hidden char leak, clipboard is exactly the payload', function () {
  fc.assert(fc.property(
    fc.array(fc.constantFrom('reveal', 'copy'), { maxLength: 6 }),
    fc.boolean(),
    function (actions, hasClipboard) {
      const r = loadScript(JS, DOM, hasClipboard ? {} : { clipboard: false });
      const d = r.win.document;
      actions.forEach(function (act) {
        d.getElementById(act === 'reveal' ? 'pd-reveal' : 'pd-copy').click();
      });
      const out = d.getElementById('pd-out');
      if (out.querySelectorAll('*').length !== 0) { return false; }       // text-only sink, no markup
      if (out.textContent.indexOf(Z) !== -1) { return false; }            // no raw zero-width leaks on screen
      for (const w of r.copied) {
        if (w.indexOf('echo "test"') !== 0) { return false; }             // starts with the first echo
        if (w.indexOf('unexpected code execution') === -1) { return false; }  // includes the second echo
        if (w.split(Z).length !== 3) { return false; }                    // exactly two zero-width separators
      }
      if (out.hidden === false && r.copied.length) {
        if (out.textContent !== r.copied[0].split(Z).join('<U+200B>')) { return false; }  // shown == copied, ZW made visible
      }
      return true;
    },
  ), { seed: 1, numRuns: 60 });
});
