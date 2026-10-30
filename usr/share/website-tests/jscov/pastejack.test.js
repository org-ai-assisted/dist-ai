'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of secure-terminal's attacks/pastejack.js -- the copy/reveal demo for the
   zero-width-space clipboard payload. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'attacks/pastejack.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
const DOM = '<button id="pd-copy">c</button><button id="pd-reveal">r</button>'
          + '<div id="pd-status"></div><div id="pd-out" hidden></div>';
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

test('missing elements: early return', function () {
  loadScript(JS, '<div></div>', {});
});

test('reveal shows payload with visible <U+200B> markers', function () {
  const { win } = loadScript(JS, DOM, {});
  win.document.getElementById('pd-reveal').click();
  const out = win.document.getElementById('pd-out');
  assert.strictEqual(out.hidden, false);
  assert.ok(out.textContent.indexOf('<U+200B>') >= 0);
  assert.ok(win.document.getElementById('pd-status').textContent.indexOf('Revealed') >= 0);
});

test('copy with clipboard resolve: status Copied', async function () {
  const { win, copied } = loadScript(JS, DOM, {});
  win.document.getElementById('pd-copy').click();
  await tick();
  assert.strictEqual(copied.length, 1);
  assert.ok(win.document.getElementById('pd-status').textContent.indexOf('Copied') >= 0);
});

test('copy with clipboard reject: shows payload', async function () {
  const { win } = loadScript(JS, DOM, {
    setup: function (w) {
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); };
    },
  });
  win.document.getElementById('pd-copy').click();
  await tick();
  assert.strictEqual(win.document.getElementById('pd-out').hidden, false);
});

test('copy without clipboard: else branch shows payload', function () {
  const { win } = loadScript(JS, DOM, { clipboard: false });
  win.document.getElementById('pd-copy').click();
  assert.strictEqual(win.document.getElementById('pd-out').hidden, false);
});
