'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of output-lies' analyze/sandbox.js -- the build-a-trap + safe-paste sandbox.
   Reads window.OL; the real analyzer is injected via require() in setup. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'analyze/sandbox.js');
const ANALYZER = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const OL = require(ANALYZER);
const withOL = function (w) { w.OL = OL; };
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

/* Full page skeleton sandbox.js assumes (it has no missing-element guards). #in is optional
   (used by the bt-send / sb-send handlers). */
function dom(opts) {
  opts = opts || {};
  return ''
    + '<input id="bt-in" value="' + (opts.btIn === undefined ? 'hello' : opts.btIn) + '">'
    + '<div id="bt-out"></div><div id="bt-verdict"></div><div id="bt-msg"></div>'
    + '<button id="bt-go">go</button>'
    + '<input type="radio" name="bt-mode" value="homoglyph">'
    + '<input type="radio" name="bt-mode" value="zerowidth">'
    + '<input type="radio" name="bt-mode" value="bidi">'
    + '<button id="bt-copy">copy</button><button id="bt-send">send</button>'
    + '<input id="sb-in" value="' + (opts.sbIn === undefined ? 'abc' : opts.sbIn) + '">'
    + '<div id="sb-raw"></div><div id="sb-safe"></div><div id="sb-tallies"></div>'
    + '<div id="sb-hint"></div><div id="sb-live"></div><div id="sb-msg"></div>'
    + '<button id="sb-copy-in">ci</button><button id="sb-copy-safe">cs</button>'
    + '<button id="sb-send">ss</button>'
    + (opts.withIn === false ? '' : '<input id="in">');
}

test('OL undefined: early return', function () {
  loadScript(JS, dom(), {});
});

test('unknown classifier class: CLSMAP fallback to m-other', function () {
  // A stub OL whose analyze yields an item with a cls NOT in CLSMAP -> the `|| 'm-other'` fallback
  // (dead with the real classifier, which only emits the 8 mapped classes). renderInto runs at load.
  loadScript(JS, dom(), {
    setup: function (w) {
      w.OL = {
        analyze: function () {
          return { items: [{ ch: '?', cp: 0x3F, info: { cls: 'bogus', name: 'x', visible: true } }],
            flagged: 1, counts: { x: 1 } };
        },
        hex: function () { return 'U+003F'; },
        toAscii: function (s) { return s; },
      };
    },
  });
});

test('full drive: forge modes, render, bt-copy proceed, bt-send, sb panel', async function () {
  const { win } = loadScript(JS, dom(), { setup: withOL });
  const d = win.document;

  // At load btRun ran with no radio checked -> 'homoglyph' (picked ? : default) on 'hello'.
  assert.ok(d.getElementById('bt-verdict').textContent.indexOf('Forged') >= 0);  // flagged -> dirty

  // zerowidth mode via radio change (picked truthy; mode 2nd ternary)
  const zw = d.querySelector('input[value=zerowidth]');
  zw.checked = true;
  zw.dispatchEvent(new win.Event('change'));
  // bidi mode
  const bd = d.querySelector('input[value=bidi]');
  bd.checked = true;
  bd.dispatchEvent(new win.Event('change'));
  // back to homoglyph
  const hg = d.querySelector('input[value=homoglyph]');
  hg.checked = true;
  hg.dispatchEvent(new win.Event('change'));

  // bt-copy: forged present + clipboard present -> writeText.then -> flash
  d.getElementById('bt-copy').click();
  await tick();
  assert.strictEqual(d.getElementById('bt-msg').textContent, '');   // flash set then syncTimers cleared

  // bt-send: #in present + forged present -> set value, dispatch input, hash
  d.getElementById('bt-send').click();
  assert.ok(d.getElementById('in').value.length > 0);

  // sb panel: sb-in has 'abc' (pure ascii) -> stripped 0 branch already ran at load; now unsafe input
  const sbIn = d.getElementById('sb-in');
  sbIn.value = 'a' + String.fromCodePoint(0x0430, 0x200B) + 'b';   // 2 unsafe -> plural 's'
  sbIn.dispatchEvent(new win.Event('input'));
  assert.ok(d.getElementById('sb-tallies').textContent.indexOf('refused') >= 0);
  sbIn.value = 'a' + String.fromCodePoint(0x0430);   // exactly 1 unsafe -> singular (stripped === 1)
  sbIn.dispatchEvent(new win.Event('input'));
  assert.ok(d.getElementById('sb-tallies').textContent.indexOf('1 unsafe codepoint ') >= 0);

  // sb-copy-in + sb-copy-safe with value -> sbCopy resolve
  d.getElementById('sb-copy-in').click();
  d.getElementById('sb-copy-safe').click();
  await tick();
  // sb-send with #in + value
  d.getElementById('sb-send').click();
});

test('forge no-change branch + single-flag pluralization', function () {
  // bt-in empty -> forgeHomoglyph('') = '' -> flagged 0 -> "No change" branch.
  const { win } = loadScript(JS, dom({ btIn: '' }), { setup: withOL });
  assert.ok(win.document.getElementById('bt-verdict').textContent.indexOf('No change') >= 0);
  // single homoglyph -> flagged === 1 (singular "codepoint")
  const { win: w2 } = loadScript(JS, dom({ btIn: 'a' }), { setup: withOL });
  assert.ok(w2.document.getElementById('bt-verdict').textContent.indexOf('1 hidden codepoint.') >= 0);
});

test('zerowidth + bidi forge edge inputs (no-match regex, no-\\S bidi)', function () {
  // zerowidth on a <3-alnum input: regex no match -> unchanged; bidi on empty: loop finds no \\S.
  const { win } = loadScript(JS, dom({ btIn: 'ab' }), { setup: withOL });
  const d = win.document;
  const zw = d.querySelector('input[value=zerowidth]');
  zw.checked = true; zw.dispatchEvent(new win.Event('change'));   // 'ab' -> no 3-alnum match
  const bd = d.querySelector('input[value=bidi]');
  // set empty then bidi: forgeBidi('') -> parts [''], no \\S
  d.getElementById('bt-in').value = '';
  bd.checked = true; bd.dispatchEvent(new win.Event('change'));
});

test('bt-copy no-op when forged empty (1st || operand)', function () {
  const { win } = loadScript(JS, dom({ btIn: '' }), { setup: withOL });
  win.document.getElementById('bt-copy').click();   // forged '' -> return
});

test('clipboard absent: bt-copy 2nd operand, sbCopy unavailable', function () {
  const { win } = loadScript(JS, dom(), {
    clipboard: false,
    syncTimers: false,
    setup: function (w) { withOL(w); w.setTimeout = function () { return 7; }; }, // keep flash visible
  });
  const d = win.document;
  d.getElementById('bt-copy').click();              // !navigator.clipboard -> return
  d.getElementById('sb-copy-in').click();           // sbCopy -> else -> 'clipboard unavailable'
  assert.ok(d.getElementById('sb-msg').textContent.indexOf('unavailable') >= 0);
});

test('clipboard without writeText: bt-copy 3rd operand', function () {
  const { win } = loadScript(JS, dom(), {
    setup: function (w) { withOL(w); w.navigator.clipboard = {}; },
  });
  win.document.getElementById('bt-copy').click();   // !navigator.clipboard.writeText -> return
});

test('sbCopy reject: clipboard blocked', async function () {
  const { win } = loadScript(JS, dom(), {
    syncTimers: false,
    setup: function (w) {
      withOL(w);
      w.setTimeout = function () { return 7; };      // keep flash visible
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); };
    },
  });
  win.document.getElementById('sb-copy-in').click();
  await tick();
  assert.ok(win.document.getElementById('sb-msg').textContent.indexOf('blocked') >= 0);
});

test('no #in: bt-send / sb-send if-x false; empty sb-in resets live', function () {
  const { win } = loadScript(JS, dom({ withIn: false, sbIn: '' }), { setup: withOL });
  const d = win.document;
  d.getElementById('bt-send').click();              // x null -> if(x && forged) false
  d.getElementById('sb-send').click();              // x null
  // sb-in empty at load -> sbRun !str branch (sbLive hidden, sbHint shown)
  assert.strictEqual(d.getElementById('sb-live').hidden, true);
  // empty sb-copy-in/safe: if(sbIn.value) false
  d.getElementById('sb-copy-in').click();
  d.getElementById('sb-copy-safe').click();
});
