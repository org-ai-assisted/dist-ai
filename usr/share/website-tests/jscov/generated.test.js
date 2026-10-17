'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of the generated per-build globals: search-index.js (window.MWSEARCH) and
   page-previews.js (window.MWPREVIEWS) -- one global assignment each, zero branches. Staged from
   a wiki stage root. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

// Only runs when a wiki stage root was staged; otherwise these generated files are absent and
// their gating is a Phase-4 concern (see README). Register no tests for a family-only run.
if (!require('node:fs').existsSync(sitePath('kicksecure-stage.github.io', 'search-index.js'))) { return; }

test('search-index.js sets window.MWSEARCH', function () {
  const { win } = loadScript(sitePath('kicksecure-stage.github.io', 'search-index.js'), '', {});
  assert.ok(Array.isArray(win.MWSEARCH));
});

test('page-previews.js sets window.MWPREVIEWS', function () {
  const { win } = loadScript(sitePath('kicksecure-stage.github.io', 'page-previews.js'), '', {});
  assert.ok(win.MWPREVIEWS && typeof win.MWPREVIEWS === 'object');
});
