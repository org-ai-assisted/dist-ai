'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of output-lies' analyze/ui.js -- the x-ray tool page wiring (render, samples,
   copy-ASCII, sessionStorage preload). Reads window.OL; the real analyzer is injected via
   require() in setup. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'analyze/ui.js');
const ANALYZER = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const OL = require(ANALYZER);
const withOL = function (w) { w.OL = OL; };
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

const DOM =
  '<textarea id="in"></textarea><div id="out"></div><div id="verdict"></div><div id="tallies"></div>'
  + '<div id="samples"><button data-k="homoglyph">h</button><button data-k="bogus">b</button>'
  + '<span id="notbtn">x</span></div>'
  + '<button id="copyascii">copy</button><div id="copymsg"></div>';
const DOM_NOCOPY =
  '<textarea id="in"></textarea><div id="out"></div><div id="verdict"></div><div id="tallies"></div>'
  + '<div id="samples"></div>';

test('render: empty, clean, dirty (chip visible + invisible), samples, copy resolve', async function () {
  const { win, copied } = loadScript(JS, DOM, { setup: withOL });   // render() at load: empty -> if(!str)
  const d = win.document;
  const input = d.getElementById('in');

  input.value = 'git commit -m ok';                         // clean ASCII
  input.dispatchEvent(new win.Event('input'));
  assert.ok(d.getElementById('verdict').textContent.indexOf('Clean') >= 0);

  input.value = 'a' + String.fromCodePoint(0x0430, 0x200B) + 'b';   // homoglyph (visible) + zero-width
  input.dispatchEvent(new win.Event('input'));
  assert.ok(d.getElementById('verdict').textContent.indexOf('suspicious') >= 0);
  assert.ok(d.getElementById('tallies').textContent.indexOf('Breakdown') >= 0);

  d.querySelector('[data-k=homoglyph]').click();            // SAMPLES hit
  assert.ok(input.value.indexOf('ex') >= 0);
  d.querySelector('[data-k=bogus]').click();                // SAMPLES miss -> ''
  assert.strictEqual(input.value, '');
  d.getElementById('notbtn').click();                       // closest('button') null -> if(!btn) return

  input.value = 'x' + String.fromCodePoint(0x0430);
  input.dispatchEvent(new win.Event('input'));
  d.getElementById('copyascii').click();                    // clipboard resolve -> ok() (copymsg cleared)
  await tick();
  assert.deepStrictEqual(copied, ['x']);                    // toAscii('x'+U+0430) written to clipboard
});

test('copy with clipboard reject: strips in place', async function () {
  const { win } = loadScript(JS, DOM, {
    setup: function (w) {
      withOL(w);
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); };
    },
  });
  const input = win.document.getElementById('in');
  input.value = 'y' + String.fromCodePoint(0x0435);
  input.dispatchEvent(new win.Event('input'));
  win.document.getElementById('copyascii').click();
  await tick();
  assert.strictEqual(input.value, 'y');                     // reject -> stripped in place (non-transient)
});

test('copy without clipboard: strips in place (else)', function () {
  const { win } = loadScript(JS, DOM, { clipboard: false, setup: withOL });
  const input = win.document.getElementById('in');
  input.value = 'z' + String.fromCodePoint(0x0441);
  input.dispatchEvent(new win.Event('input'));
  win.document.getElementById('copyascii').click();
  assert.strictEqual(input.value, 'z');                     // else -> stripped in place
});

test('no #copyascii: if-copyBtn false', function () {
  loadScript(JS, DOM_NOCOPY, { setup: withOL });
});

test('sessionStorage preload: pre !== null path', function () {
  const { win } = loadScript(JS, DOM, {
    setup: function (w) { withOL(w); w.sessionStorage.setItem('ol-xray-input', 'preloaded'); },
  });
  assert.strictEqual(win.document.getElementById('in').value, 'preloaded');
});

test('sessionStorage throws: catch swallows', function () {
  const { win } = loadScript(JS, DOM, {
    setup: function (w) {
      withOL(w);
      // jsdom's Storage methods are non-writable; redefine the whole accessor so getItem throws.
      Object.defineProperty(w, 'sessionStorage', {
        configurable: true,
        value: { getItem: function () { throw new Error('unavailable'); } },
      });
    },
  });
  assert.ok(win.document.getElementById('in'));   // loaded without throwing (catch swallowed)
});

test('unknown classifier class: CLSMAP fallback to m-other', function () {
  // Stub OL yielding an item with a cls NOT in CLSMAP -> chip()'s `|| 'm-other'` fallback (dead
  // with the real classifier). render() runs the items loop at load before the if(!str) return.
  loadScript(JS, DOM, {
    setup: function (w) {
      w.OL = {
        analyze: function () {
          return { items: [{ ch: '?', cp: 0x3F, info: { cls: 'bogus', name: 'x', visible: false } }],
            flagged: 1, counts: { x: 1 } };
        },
        hex: function () { return 'U+003F'; },
        toAscii: function (s) { return s; },
      };
    },
  });
});
