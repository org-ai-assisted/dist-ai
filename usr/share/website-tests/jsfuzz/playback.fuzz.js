'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for output-lies' terminal/playback.js -- the framed terminal-state playback
   primitive (no external library; every frame set via textContent). It reads only its own DOM (no
   globals or sibling files), so nothing is staged with the `+` prefix. Curated DOM configs (reused
   from the jscov sibling) drive every branch to deterministic 100% c8; the invariants assert the
   two attacker/robustness properties that matter for a stepper: for ANY number of replays the
   step index never runs out of FRAMES bounds (a full play always terminates at the END frame
   without throwing), and playback injects no markup (screen/caption are textContent-only). */

const { fc, test, sitePath } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'terminal/playback.js');

const DOM = '<div id="as-screen"></div><div id="as-cap"></div>'
          + '<button id="as-play">Play</button><div id="as-state"></div>';
const DOM_NOSTATE = '<div id="as-screen"></div><div id="as-cap"></div><button id="as-play">Play</button>';

/* --- coverage: every branch, deterministic (reuses the proven jscov DOM configs) --- */

test('playback: missing elements -> early return (if(!screen||!cap||!btn) true)', function () {
  loadScript(JS, '<div></div>', {});   // none of the required ids present
});

test('playback: full play walks all frames to END (syncTimers recurses; if-state true)', function () {
  const r = loadScript(JS, DOM, {});                 // syncTimers default -> setTimeout runs inline
  const d = r.win.document;
  d.getElementById('as-play').click();               // play -> step recurses i=0,1 (true) then last (false->END)
  if (d.getElementById('as-cap').textContent.indexOf('scrollback') < 0) { throw new Error('END caption not reached'); }
  const btn = d.getElementById('as-play');
  if (btn.textContent !== 'Replay') { throw new Error('button not reset to Replay'); }
  if (btn.disabled !== false) { throw new Error('button should be re-enabled at END'); }
  if (d.getElementById('as-state').textContent.indexOf('without a trace') < 0) { throw new Error('state text not set'); }
});

test('playback: play without #as-state completes (if(state) false arms)', function () {
  const r = loadScript(JS, DOM_NOSTATE, {});
  r.win.document.getElementById('as-play').click();
  if (r.win.document.getElementById('as-cap').textContent.indexOf('scrollback') < 0) { throw new Error('END not reached without state'); }
});

test('playback: second play clears the pending timer (stopTimer if(timer) true)', function () {
  const r = loadScript(JS, DOM, {
    syncTimers: false,
    setup: function (w) { w.setTimeout = function () { return 7; }; },   // freeze after first step()
  });
  const btn = r.win.document.getElementById('as-play');
  btn.click();            // step(0): timer = 7; play() set btn.disabled = true
  btn.disabled = false;   // a disabled button swallows clicks; re-enable so the 2nd play fires
  btn.click();            // play -> stopTimer -> if(timer) [7] true -> clearTimeout(7)
});

/* --- invariants --- */

/* Index-bounds / replay safety: for ANY replay count (and with #as-state present or not), a full
   inline play always terminates at the END frame (caption contains 'scrollback') with the button
   re-enabled, and never throws. A throw would mean show(n) indexed FRAMES out of range (e.g. an
   off-by-one in the `i < FRAMES.length - 1` guard stepping to FRAMES[3].cap); reaching the END
   caption proves the last in-bounds frame painted and the guard fell through exactly once. */
test('playback: any replay count terminates in-bounds at END, button re-enabled', function () {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 6 }),
    fc.boolean(),
    function (replays, withState) {
      const r = loadScript(JS, withState ? DOM : DOM_NOSTATE, {});
      const d = r.win.document;
      const btn = d.getElementById('as-play');
      for (let k = 0; k < replays; k++) {
        btn.disabled = false;   // re-enable between replays (a disabled button swallows the click)
        btn.click();            // syncTimers inline -> walks the whole sequence synchronously
      }
      if (d.getElementById('as-cap').textContent.indexOf('scrollback') < 0) { return false; }
      if (btn.textContent !== 'Replay') { return false; }
      if (btn.disabled !== false) { return false; }
      return true;
    },
  ), { seed: 1, numRuns: 50 });
});

/* No-markup guarantee: frames are painted with textContent only, so after any play the screen and
   caption nodes carry ZERO element children -- no frame body (even the ALT box-drawing art) is ever
   parsed as HTML. A regression to innerHTML would be caught the moment any frame carried a tag. */
test('playback: screen and caption are textContent-only (no element children)', function () {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 6 }),
    function (replays) {
      const r = loadScript(JS, DOM, {});
      const d = r.win.document;
      const btn = d.getElementById('as-play');
      for (let k = 0; k < replays; k++) { btn.disabled = false; btn.click(); }
      const screen = d.getElementById('as-screen');
      const cap = d.getElementById('as-cap');
      if (screen.childElementCount !== 0) { return false; }
      if (cap.childElementCount !== 0) { return false; }
      if (typeof screen.textContent !== 'string' || screen.textContent.length === 0) { return false; }
      return true;
    },
  ), { seed: 1, numRuns: 40 });
});
