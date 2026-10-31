'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for secure-terminal's copy.js -- the rich copy-button variant: a flash()
   with a restore timer, a success path, and a clipboard-reject fallback that range-selects the
   command so the "Press Ctrl+C" hint has something to copy. The command textContent is the only
   author-influenced input to the clipboard sink. Invariants assert COPY FIDELITY on success (the
   clipboard receives the command text verbatim), that a DENIED write never records a copy and
   always surfaces the hint (never a silent false success), and that clicking never throws for any
   command text across all three outcomes. Curated DOM configs (mirroring the proven jscov
   st-copy.test.js) drive every branch to deterministic 100% c8. */

const { fc, test, sitePath, adversarialString } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'copy.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
const CMD = 'sudo apt update';
function box(cmdText) {
  /* button ships `hidden` like the real page (progressive enhancement); the IIFE reveals it. */
  return '<div class="copybox"><code class="cmd">' + cmdText + '</code>'
       + '<button class="copybtn" hidden>Copy</button></div>';
}
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };
/* Freeze restore: a non-null timer id makes the deferred label-restore never fire, so the flashed
   label (and the if(timer) TRUE arm on a second flash) are observable. */
const freezeTimer = function (w) { w.setTimeout = function () { return 7; }; };
const rejectWrite = function (w) {
  w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('denied')); };
};

/* --- coverage: every branch, deterministic --- */

/* !navigator.clipboard TRUE -> IIFE early-returns. */
test('st copy: no clipboard early-returns', function () {
  const r = loadScript(JS, box(CMD), { clipboard: false });
  if (!r.win.document.querySelector('.copybtn').hidden) { throw new Error('no clipboard must leave the button hidden'); }
  if (r.copied.length !== 0) { throw new Error('nothing copied without clipboard'); }
});

/* !cmd || !btn TRUE (code present, button absent) -> box skipped. */
test('st copy: box missing the button is skipped', function () {
  const r = loadScript(JS, '<div class="copybox"><code class="cmd">x</code></div>', {});
  if (r.copied.length !== 0) { throw new Error('box without a button must not wire a copy'); }
});

/* Success + sync restore: click copies the command, flash("Copied",true) sets the label + ok
   (toggle ok TRUE arm), first flash has timer null (if(timer) FALSE arm), the sync setTimeout runs
   the restore (base + remove ok + timer=null). */
test('st copy: click copies, flashes Copied, restores base', async function () {
  const r = loadScript(JS, box(CMD), {});
  const btn = r.win.document.querySelector('.copybtn');
  if (btn.hidden) { throw new Error('button should be revealed'); }
  btn.click();
  await tick();
  if (r.copied.length !== 1 || r.copied[0] !== CMD) {
    throw new Error('clipboard got the wrong text: ' + JSON.stringify(r.copied));
  }
  if (btn.textContent !== 'Copy') { throw new Error('label not restored to base'); }
  if (btn.classList.contains('ok')) { throw new Error('ok class not cleared'); }
});

/* Second flash clears the pending timer: frozen timer id stays non-null, so the second click's
   flash hits if(timer) -> clearTimeout(7) (the TRUE arm). */
test('st copy: a second flash clears the pending restore timer', async function () {
  const r = loadScript(JS, box(CMD), { syncTimers: false, setup: freezeTimer });
  const btn = r.win.document.querySelector('.copybtn');
  btn.click(); await tick();   // timer = 7 (restore frozen)
  btn.click(); await tick();   // if(timer) TRUE -> clearTimeout(7)
  if (btn.textContent !== 'Copied') { throw new Error('second flash should re-show Copied'); }
});

/* Clipboard reject: the failure callback range-selects the command (createRange/selectNodeContents
   + getSelection) and flashes the hint with ok=false (toggle ok FALSE arm). */
test('st copy: denied write selects the command and flashes the hint', async function () {
  const r = loadScript(JS, box(CMD), {
    syncTimers: false,
    setup: function (w) { freezeTimer(w); rejectWrite(w); },
  });
  const btn = r.win.document.querySelector('.copybtn');
  btn.click();
  await tick();
  if (btn.textContent !== 'Press Ctrl+C') { throw new Error('hint not flashed on denial'); }
  if (btn.classList.contains('ok')) { throw new Error('ok must be cleared on denial'); }
  if (r.copied.length !== 0) { throw new Error('a denied write must not record a copy'); }
});

/* Clipboard reject AND the selection throws -> the try/catch swallows it, hint still flashes. */
test('st copy: denied write with a throwing selection still flashes the hint', async function () {
  const r = loadScript(JS, box(CMD), {
    syncTimers: false,
    setup: function (w) {
      freezeTimer(w); rejectWrite(w);
      w.document.createRange = function () { throw new Error('no range'); };
    },
  });
  const btn = r.win.document.querySelector('.copybtn');
  btn.click();
  await tick();
  if (btn.textContent !== 'Press Ctrl+C') { throw new Error('hint must flash despite selection throw'); }
});

/* --- invariants --- */

/* COPY FIDELITY: for ANY command text, a successful click writes EXACTLY that textContent once --
   the glue never truncates, re-encodes, or injects content the DOM did not hold; with the sync
   restore the label returns to its base. */
test('st copy: success writes the command verbatim and restores the label', async function () {
  await fc.assert(fc.asyncProperty(adversarialString, async function (s) {
    const r = loadScript(JS, box(''), {});
    const d = r.win.document;
    d.querySelector('.cmd').textContent = s;   // via DOM API: no markup parsing
    const btn = d.querySelector('.copybtn');
    let threw = false;
    try { btn.click(); } catch (e) { threw = true; }
    await tick();
    if (threw) { return false; }
    const src = d.querySelector('.cmd').textContent;
    return r.copied.length === 1 && r.copied[0] === src && btn.textContent === 'Copy';
  }), { seed: 1, numRuns: 50 });
});

/* DENIAL SAFETY: for ANY command text, a denied write NEVER records a copy (no silent false
   success) and ALWAYS surfaces the "Press Ctrl+C" hint; clicking never throws. */
test('st copy: a denied write never reports success, always hints', async function () {
  await fc.assert(fc.asyncProperty(adversarialString, async function (s) {
    const r = loadScript(JS, box(''), {
      syncTimers: false,
      setup: function (w) { freezeTimer(w); rejectWrite(w); },
    });
    const d = r.win.document;
    d.querySelector('.cmd').textContent = s;
    const btn = d.querySelector('.copybtn');
    let threw = false;
    try { btn.click(); } catch (e) { threw = true; }
    await tick();
    if (threw) { return false; }
    return r.copied.length === 0 && btn.textContent === 'Press Ctrl+C';
  }), { seed: 1, numRuns: 50 });
});
