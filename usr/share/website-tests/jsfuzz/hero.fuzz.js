'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for secure-terminal's hero.js -- the before/after comparison slider.
   The author/attacker-influenced surface is the data-start attribute (an arbitrary string the
   page markup supplies) and the keyboard stepping; both feed set(), whose Math.max/Math.min clamp
   is the safety bound. Invariants assert the divider position stays inside [0, 100] for ANY
   data-start string (negative, huge, NaN, Infinity, prototype-name, adversarial) and for ANY
   keyboard sequence; curated DOM configs drive every branch of the IIFE to deterministic 100% c8.
   jsdom lacks pointer capture + layout geometry, so getBoundingClientRect / setPointerCapture /
   releasePointerCapture are stubbed per case (as in the jscov sibling). */

const { fc, test, sitePath, adversarialString } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'hero.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)

/* HTML-escape the data-start value so an adversarial string lands in the attribute verbatim
   (and cannot break out of it) -- the test then fuzzes the exact string parseFloat() sees. */
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function cmpDom(dataStart) {
  return '<div class="herocmp"' + (dataStart === undefined ? '' : ' data-start="' + esc(dataStart) + '"') + '>'
    + '<div class="herocmp-stage"></div><div class="herocmp-top"></div>'
    + '<div class="herocmp-handle"></div></div>';
}
function pev(win, type, p) {
  const e = new win.MouseEvent(type, {
    bubbles: true, cancelable: true,
    clientX: p.clientX || 0, clientY: p.clientY || 0, button: p.button || 0,
  });
  Object.defineProperty(e, 'pointerId', { value: p.pointerId === undefined ? 1 : p.pointerId, configurable: true });
  return e;
}
function kev(win, key, shift) {
  return new win.KeyboardEvent('keydown', { key: key, shiftKey: !!shift, bubbles: true, cancelable: true });
}
function parts(win) {
  const d = win.document;
  return { stage: d.querySelector('.herocmp-stage'), handle: d.querySelector('.herocmp-handle'),
    top: d.querySelector('.herocmp-top') };
}

/* --- coverage: every branch of the IIFE, deterministic (mirrors the jscov DOM configs) --- */

test('hero: no .herocmp and missing child both early-return', function () {
  loadScript(JS, '<div></div>', {});                                   // !cmp -> return
  loadScript(JS, '<div class="herocmp"><div class="herocmp-stage"></div></div>', {});  // !top -> return
});

test('hero: NaN data-start defaults to 50; a valid data-start is honored', function () {
  const r = loadScript(JS, cmpDom(), {});                              // no attr -> parseFloat(null) NaN -> 50
  if (r.win.document.querySelector('.herocmp-top').style.width !== '50%') { throw new Error('NaN did not default to 50'); }
  const r2 = loadScript(JS, cmpDom('30'), {});
  if (r2.win.document.querySelector('.herocmp-top').style.width !== '30%') { throw new Error('valid data-start ignored'); }
});

test('hero: full drag -- geometry>0, capture present, release, trailing click cancels', function () {
  const r = loadScript(JS, cmpDom('30'), {});
  const { stage, top } = parts(r.win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200, top: 0, height: 100 }; };
  stage.setPointerCapture = function () {};
  stage.releasePointerCapture = function () {};
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 50, clientY: 50, pointerId: 1, button: 0 }));
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 100, clientY: 50, pointerId: 1 }));  // past threshold -> drag start
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 120, clientY: 50, pointerId: 1 }));  // continue (dragging already)
  if (top.style.width !== '60%') { throw new Error('drag did not track pointer (120/200)'); }
  stage.dispatchEvent(pev(r.win, 'pointerup', { pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'click', {}));    // moved -> preventDefault + reset
});

test('hero: drag with zero-width geometry and no pointer-capture API', function () {
  const r = loadScript(JS, cmpDom('40'), {});
  const { stage, top } = parts(r.win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 0 }; };   // width<=0 -> pctFrom returns pct
  stage.setPointerCapture = undefined;
  stage.releasePointerCapture = undefined;
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 80, clientY: 10, pointerId: 1 }));  // drag, width 0
  if (top.style.width !== '40%') { throw new Error('zero-width geometry must leave pct unchanged'); }
  stage.dispatchEvent(pev(r.win, 'pointerup', { pointerId: 1 }));   // dragging but no releasePointerCapture
  stage.dispatchEvent(pev(r.win, 'click', {}));
});

test('hero: small movement stays a click (no drag); not-moved click falls through', function () {
  const r = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(r.win);
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 30, clientY: 30, pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 32, clientY: 31, pointerId: 1 }));  // below threshold -> return
  stage.dispatchEvent(pev(r.win, 'pointerup', { pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'click', {}));    // moved false -> fall through
});

test('hero: second pointer (pinch) aborts an active drag; subsequent move ignored', function () {
  const r = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(r.win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200 }; };
  let released = 0;
  stage.setPointerCapture = function () {};
  stage.releasePointerCapture = function () { released += 1; };
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 90, clientY: 10, pointerId: 1 }));  // dragging = true
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 60, clientY: 10, pointerId: 2 }));  // down>=2 -> abortDrag
  if (released !== 1) { throw new Error('pinch did not release capture'); }
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 70, clientY: 10, pointerId: 2 }));  // down>=2 -> ignored
});

test('hero: non-primary button ignored; stray move/up with no active pointer; id mismatch', function () {
  const r = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(r.win);
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 5, clientY: 5, pointerId: 1, button: 2 }));  // button!==0 -> return
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 9, clientY: 9, pointerId: 9 }));   // active null -> return
  stage.dispatchEvent(pev(r.win, 'pointerup', { pointerId: 9 }));                              // down-- then active null
  const r2 = loadScript(JS, cmpDom('50'), {});
  const s2 = r2.win.document.querySelector('.herocmp-stage');
  s2.dispatchEvent(pev(r2.win, 'pointerdown', { clientX: 5, clientY: 5, pointerId: 1 }));
  s2.dispatchEvent(pev(r2.win, 'pointermove', { clientX: 90, clientY: 5, pointerId: 2 }));     // id 2 != active 1 -> return
});

test('hero: keyboard arrows (step 2), shift (step 10), Home, End, ignored key', function () {
  const r = loadScript(JS, cmpDom('50'), {});
  const { handle, top } = parts(r.win);
  handle.dispatchEvent(kev(r.win, 'ArrowLeft'));         // 50 -> 48
  if (top.style.width !== '48%') { throw new Error('ArrowLeft step wrong'); }
  handle.dispatchEvent(kev(r.win, 'ArrowRight', true));  // shift step 10: 48 -> 58
  if (top.style.width !== '58%') { throw new Error('shift ArrowRight step wrong'); }
  handle.dispatchEvent(kev(r.win, 'Home'));              // -> 0
  if (top.style.width !== '0%') { throw new Error('Home did not go to 0'); }
  handle.dispatchEvent(kev(r.win, 'End'));               // -> 100
  if (top.style.width !== '100%') { throw new Error('End did not go to 100'); }
  handle.dispatchEvent(kev(r.win, 'a'));                 // not handled -> no branch taken
});

test('hero: setPointerCapture/releasePointerCapture throwing is swallowed (move + up)', function () {
  const r = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(r.win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200 }; };
  stage.setPointerCapture = function () { throw new Error('nope'); };
  stage.releasePointerCapture = function () { throw new Error('nope'); };
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 90, clientY: 10, pointerId: 1 }));  // setPointerCapture throws -> catch
  stage.dispatchEvent(pev(r.win, 'pointerup', { pointerId: 1 }));                               // releasePointerCapture throws -> catch
});

test('hero: abortDrag catch -- releasePointerCapture throws during pinch', function () {
  const r = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(r.win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200 }; };
  stage.setPointerCapture = function () {};
  stage.releasePointerCapture = function () { throw new Error('nope'); };
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(r.win, 'pointermove', { clientX: 90, clientY: 10, pointerId: 1 }));  // dragging = true
  stage.dispatchEvent(pev(r.win, 'pointerdown', { clientX: 60, clientY: 10, pointerId: 2 }));  // pinch -> abortDrag -> release throws -> catch
});

/* --- invariants --- */

/* PRIMARY: for ANY data-start string the clamped divider position is always inside [0, 100] and
   aria-valuenow is an integer in [0, 100]. This is the Math.max(0, Math.min(100, p)) safety bound:
   '200'/'1e9'/Infinity clamp to 100, '-50'/-Infinity to 0, NaN/garbage/prototype-name default to
   50 -- none ever escapes the track. Non-vacuous: without the clamp '200' would set width 200%. */
test('hero: data-start never drives the divider outside [0, 100]', function () {
  fc.assert(fc.property(
    fc.oneof(
      fc.constantFrom('50', '0', '100', '-50', '200', '1e9', '-1e9', 'NaN', 'abc', '',
        '   12  ', '__proto__', 'constructor', 'prototype', 'Infinity', '-Infinity',
        '3.14', '1e309', '99.9999', '-0', '+100', '  -300.5 ', '1e400'),
      adversarialString,
      fc.integer({ min: -1000000, max: 1000000 }).map(String),
      fc.double({ noNaN: false }).map(String),
    ),
    function (ds) {
      const r = loadScript(JS, cmpDom(ds), {});
      const w = parseFloat(r.win.document.querySelector('.herocmp-top').style.width);
      if (!(w >= 0 && w <= 100)) { return false; }
      const now = Number(r.win.document.querySelector('.herocmp-handle').getAttribute('aria-valuenow'));
      if (!(Number.isInteger(now) && now >= 0 && now <= 100)) { return false; }
      return true;
    },
  ), { seed: 1, numRuns: 80 });
});

/* For ANY keyboard sequence (arrows, Home, End, shift, noise keys), the divider position stays
   inside [0, 100] -- every key routes through set()'s clamp, so no accumulation of steps can
   over/undershoot the track. */
test('hero: no keyboard sequence drives the divider outside [0, 100]', function () {
  fc.assert(fc.property(
    fc.array(fc.record({
      key: fc.constantFrom('ArrowLeft', 'ArrowRight', 'Home', 'End', 'x', 'Enter'),
      shift: fc.boolean(),
    }), { maxLength: 60 }),
    function (seq) {
      const r = loadScript(JS, cmpDom('50'), {});
      const handle = r.win.document.querySelector('.herocmp-handle');
      const top = r.win.document.querySelector('.herocmp-top');
      for (const s of seq) {
        handle.dispatchEvent(kev(r.win, s.key, s.shift));
        const w = parseFloat(top.style.width);
        if (!(w >= 0 && w <= 100)) { return false; }
      }
      return true;
    },
  ), { seed: 1, numRuns: 60 });
});
