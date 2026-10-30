'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of output-lies' terminal/xray.js -- the live board x-ray. It reads the shared
   analyzer as the window.OL global; the real analyzer is injected via require() in setup. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'terminal/xray.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
const ANALYZER = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const withOL = function (w) { w.OL = require(ANALYZER); };

test('OL undefined: early return', function () {
  loadScript(JS, '<div id="board-xray"></div>', {});   // no OL injected
});

test('#board-xray missing: early return', function () {
  loadScript(JS, '<div></div>', { setup: withOL });
});

test('full render: walks every row (ASCII, flagged, honest) and totals', function () {
  const { win } = loadScript(JS, '<div id="board-xray"></div>', { setup: withOL });
  const box = win.document.getElementById('board-xray');
  assert.ok(box.textContent.indexOf('hidden or disguised codepoints revealed') >= 0);
  assert.ok(box.textContent.indexOf('NOT an attack') >= 0);   // the honest row
});
