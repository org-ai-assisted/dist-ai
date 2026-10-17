'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of secure-terminal's copy.js -- the rich copy-button variant with a flash timer
   and a clipboard-reject fallback that range-selects the command. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'copy.js');
const BOX = '<div class="copybox"><code class="cmd">sudo apt update</code>'
          + '<button class="copybtn">Copy</button></div>';
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

test('no clipboard: IIFE early-returns', function () {
  loadScript(JS, BOX, { clipboard: false });
});

test('box missing btn: skipped', function () {
  loadScript(JS, '<div class="copybox"><code class="cmd">x</code></div>', {});
});

test('click copies, flashes, timeout restores base', async function () {
  const { win, copied } = loadScript(JS, BOX, {});
  const btn = win.document.querySelector('.copybtn');
  btn.click();
  await tick();
  assert.deepStrictEqual(copied, ['sudo apt update']);
  assert.strictEqual(btn.textContent, 'Copy');            // restore ran (syncTimers)
  assert.strictEqual(btn.classList.contains('ok'), false);
});

test('second flash clears the pending timer (if-timer true)', async function () {
  const { win } = loadScript(JS, BOX, {
    syncTimers: false,
    setup: function (w) { w.setTimeout = function () { return 7; }; }, // leave timer non-null
  });
  const btn = win.document.querySelector('.copybtn');
  btn.click(); await tick();   // timer = 7
  btn.click(); await tick();   // if(timer) -> clearTimeout(7)
  assert.strictEqual(btn.textContent, 'Copied');           // restore no-op'd
});

test('clipboard reject: range-select fallback, flashes hint', async function () {
  const { win } = loadScript(JS, BOX, {
    syncTimers: false,
    setup: function (w) {
      w.setTimeout = function () { return 7; };             // freeze restore so the hint is observable
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('denied')); };
    },
  });
  const btn = win.document.querySelector('.copybtn');
  btn.click();
  await tick();
  assert.strictEqual(btn.textContent, 'Press Ctrl+C');
});

test('clipboard reject + selection throws: catch swallows, still flashes hint', async function () {
  const { win } = loadScript(JS, BOX, {
    syncTimers: false,
    setup: function (w) {
      w.setTimeout = function () { return 7; };
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('denied')); };
      w.document.createRange = function () { throw new Error('no range'); }; // force the catch
    },
  });
  const btn = win.document.querySelector('.copybtn');
  btn.click();
  await tick();
  assert.strictEqual(btn.textContent, 'Press Ctrl+C');
});
