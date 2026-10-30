'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of secure-terminal's hero.js -- the before/after slider (pointer drag vs click,
   two-finger pinch abort, keyboard). jsdom lacks pointer-capture + layout geometry, so the stage's
   getBoundingClientRect / setPointerCapture / releasePointerCapture are set explicitly per case. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'hero.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)

function cmpDom(dataStart) {
  return '<div class="herocmp"' + (dataStart === undefined ? '' : ' data-start="' + dataStart + '"') + '>'
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
  return { stage: d.querySelector('.herocmp-stage'), handle: d.querySelector('.herocmp-handle') };
}

test('no .herocmp: early return', function () {
  loadScript(JS, '<div></div>', {});
});

test('missing stage/top/handle child: early return', function () {
  loadScript(JS, '<div class="herocmp"><div class="herocmp-stage"></div></div>', {});
});

test('NaN data-start defaults to 50; valid data-start honored', function () {
  const { win } = loadScript(JS, cmpDom(), {});                    // no data-start -> parseFloat(null) NaN -> 50
  assert.strictEqual(win.document.querySelector('.herocmp-top').style.width, '50%');
  const { win: w2 } = loadScript(JS, cmpDom('30'), {});            // valid
  assert.strictEqual(w2.document.querySelector('.herocmp-top').style.width, '30%');
});

test('full drag: geometry>0, pointer-capture present, release, click cancels', function () {
  const { win } = loadScript(JS, cmpDom('30'), {});
  const { stage } = parts(win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200, top: 0, height: 100 }; };
  stage.setPointerCapture = function () {};
  stage.releasePointerCapture = function () {};
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 50, clientY: 50, pointerId: 1, button: 0 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 100, clientY: 50, pointerId: 1 }));  // start drag
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 120, clientY: 50, pointerId: 1 }));  // continue
  assert.strictEqual(win.document.querySelector('.herocmp-top').style.width, '60%');          // 120/200
  stage.dispatchEvent(pev(win, 'pointerup', { pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'click', {}));   // moved -> preventDefault + reset
});

test('drag with zero-width geometry and no pointer-capture API', function () {
  const { win } = loadScript(JS, cmpDom('40'), {});
  const { stage } = parts(win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 0 }; };  // width<=0 -> pctFrom returns pct
  stage.setPointerCapture = undefined;
  stage.releasePointerCapture = undefined;
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 80, clientY: 10, pointerId: 1 }));  // drag, width 0
  assert.strictEqual(win.document.querySelector('.herocmp-top').style.width, '40%');         // unchanged
  stage.dispatchEvent(pev(win, 'pointerup', { pointerId: 1 }));   // dragging but no releasePointerCapture
  stage.dispatchEvent(pev(win, 'click', {}));                     // moved from the drag
});

test('small movement stays a click (no drag); pointerup without drag; click not-moved', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(win);
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 30, clientY: 30, pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 32, clientY: 31, pointerId: 1 }));  // below threshold
  stage.dispatchEvent(pev(win, 'pointerup', { pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'click', {}));   // moved false -> fall through
});

test('second pointer (pinch) aborts an active drag', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200 }; };
  let released = 0;
  stage.setPointerCapture = function () {};
  stage.releasePointerCapture = function () { released += 1; };
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 90, clientY: 10, pointerId: 1 }));  // dragging = true
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 60, clientY: 10, pointerId: 2 }));  // down>=2 -> abortDrag
  assert.strictEqual(released, 1);
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 70, clientY: 10, pointerId: 2 }));  // down>=2 -> ignored
});

test('non-primary button is ignored; stray pointermove/up with no active pointer', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(win);
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 5, clientY: 5, pointerId: 1, button: 2 })); // button!==0 -> return
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 9, clientY: 9, pointerId: 9 }));   // active null -> return
  stage.dispatchEvent(pev(win, 'pointerup', { pointerId: 9 }));                              // down 0, active null
});

test('pointerId mismatch on move is ignored', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(win);
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 5, clientY: 5, pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 90, clientY: 5, pointerId: 2 }));  // id 2 != active 1 -> return
});

test('keyboard: arrows (step 2), shift (step 10), Home, End, ignored key', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { handle } = parts(win);
  const top = win.document.querySelector('.herocmp-top');
  handle.dispatchEvent(kev(win, 'ArrowLeft'));    // 50 -> 48
  assert.strictEqual(top.style.width, '48%');
  handle.dispatchEvent(kev(win, 'ArrowRight', true)); // shift step 10: 48 -> 58
  assert.strictEqual(top.style.width, '58%');
  handle.dispatchEvent(kev(win, 'Home'));         // -> 0
  assert.strictEqual(top.style.width, '0%');
  handle.dispatchEvent(kev(win, 'End'));          // -> 100
  assert.strictEqual(top.style.width, '100%');
  handle.dispatchEvent(kev(win, 'a'));            // not handled -> no branch
});

test('capture try/catch: setPointerCapture and releasePointerCapture throw', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200 }; };
  stage.setPointerCapture = function () { throw new Error('nope'); };
  stage.releasePointerCapture = function () { throw new Error('nope'); };
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 90, clientY: 10, pointerId: 1 }));  // setPointerCapture throws -> catch
  stage.dispatchEvent(pev(win, 'pointerup', { pointerId: 1 }));                               // releasePointerCapture throws -> catch
});

test('abortDrag catch: releasePointerCapture throws during pinch', function () {
  const { win } = loadScript(JS, cmpDom('50'), {});
  const { stage } = parts(win);
  stage.getBoundingClientRect = function () { return { left: 0, width: 200 }; };
  stage.setPointerCapture = function () {};
  stage.releasePointerCapture = function () { throw new Error('nope'); };
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 10, clientY: 10, pointerId: 1 }));
  stage.dispatchEvent(pev(win, 'pointermove', { clientX: 90, clientY: 10, pointerId: 1 }));  // dragging = true
  stage.dispatchEvent(pev(win, 'pointerdown', { clientX: 60, clientY: 10, pointerId: 2 }));  // pinch -> abortDrag -> release throws -> catch
});
