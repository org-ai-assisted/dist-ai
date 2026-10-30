'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of the three output-lies copy.js variants: two logically-identical simple ones
   (git-diffs-lie, paste) exercised in a loop, plus git-diffs-lie/all (simple copy + the mobile
   nav-toggle IIFE). */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const SIMPLE = [
  sitePath('output-lies.github.io', 'git-diffs-lie/copy.js'),
  sitePath('output-lies.github.io', 'paste/copy.js'),
];
const WITHNAV = sitePath('output-lies.github.io', 'git-diffs-lie/all/copy.js');
if (!require('node:fs').existsSync(WITHNAV)) { return; }   // skip when this site is absent (partial checkout)
const BOX = '<div class="copybox"><code class="cmd">cmd text</code>'
          + '<button class="copybtn">Copy</button></div>';
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

for (const JS of SIMPLE) {
  test('simple copy: no clipboard early-return [' + JS + ']', function () {
    loadScript(JS, BOX, { clipboard: false });
  });
  test('simple copy: missing cmd/btn skipped [' + JS + ']', function () {
    loadScript(JS, '<div class="copybox"></div>', {});
  });
  test('simple copy: click copies + flash + restore [' + JS + ']', async function () {
    const { win, copied } = loadScript(JS, BOX, {});
    win.document.querySelector('.copybtn').click();
    await tick();
    assert.deepStrictEqual(copied, ['cmd text']);
  });
}

test('all/copy: click copies', async function () {
  const { win, copied } = loadScript(WITHNAV, BOX, {});
  win.document.querySelector('.copybtn').click();
  await tick();
  assert.deepStrictEqual(copied, ['cmd text']);
});

test('all/copy: no clipboard early-return', function () {
  loadScript(WITHNAV, BOX, { clipboard: false });
});

test('all/copy: missing cmd/btn skipped', function () {
  loadScript(WITHNAV, '<div class="copybox"></div>', {});
});

test('all/copy: navtoggle present scroll closes, resize', function () {
  const { win } = loadScript(WITHNAV, '<input type="checkbox" id="navtoggle">' + BOX, {});
  const nt = win.document.getElementById('navtoggle');
  nt.checked = true;
  win.dispatchEvent(new win.Event('scroll'));
  assert.strictEqual(nt.checked, false);
  win.dispatchEvent(new win.Event('resize'));
});

test('all/copy: navtoggle absent returns early', function () {
  loadScript(WITHNAV, BOX, {});
});
