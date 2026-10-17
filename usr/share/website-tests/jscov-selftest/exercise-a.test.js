'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Requires (executes) a.js only; never touches b.js. With both listed in covered.txt and c8
   --all, b.js reports 0% and the gate FAILS -- the fail-closed proof that the real gate is not
   vacuous. */
const path = require('node:path');
const { test } = require('node:test');

test('jscov self-check: exercise a.js, leave b.js unexercised', function () {
  require(path.join(__dirname, 'a.js'));
});
