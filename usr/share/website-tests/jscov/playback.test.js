'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of output-lies' terminal/playback.js -- the framed terminal-state playback. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'terminal/playback.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
const DOM = '<div id="as-screen"></div><div id="as-cap"></div>'
          + '<button id="as-play">Play</button><div id="as-state"></div>';

test('missing elements: early return', function () {
  loadScript(JS, '<div></div>', {});
});

test('play walks all frames to the END (syncTimers recurses)', function () {
  const { win } = loadScript(JS, DOM, {});
  win.document.getElementById('as-play').click();
  const cap = win.document.getElementById('as-cap');
  assert.ok(cap.textContent.indexOf('scrollback') >= 0);           // END caption reached
  const btn = win.document.getElementById('as-play');
  assert.strictEqual(btn.textContent, 'Replay');
  assert.strictEqual(btn.disabled, false);
});

test('play without #as-state still completes (if-state false branches)', function () {
  const { win } = loadScript(JS,
    '<div id="as-screen"></div><div id="as-cap"></div><button id="as-play">Play</button>', {});
  win.document.getElementById('as-play').click();
});

test('second play clears the pending timer (stopTimer if-timer true)', function () {
  const { win } = loadScript(JS, DOM, {
    syncTimers: false,
    setup: function (w) { w.setTimeout = function () { return 7; }; },   // freeze after first step
  });
  const btn = win.document.getElementById('as-play');
  btn.click();            // step(0): timer = 7; play() also set btn.disabled = true
  btn.disabled = false;   // a disabled button swallows clicks; re-enable so the 2nd play fires
  btn.click();            // play -> stopTimer -> if(timer) [7] -> clearTimeout(7)
});
