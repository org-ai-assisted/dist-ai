'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Shared harness for the JS unit-coverage lane. Loads a first-party site script (a browser
   IIFE) into a fresh jsdom window via a VM context, with the REAL filename so c8 attributes
   coverage to the source file. Returns the window + recorders so a test can exercise every
   branch to 100%. No network; pure jsdom. */

const { JSDOM } = require('jsdom');
const vm = require('vm');
const fs = require('fs');

/* loadScript(jsPath, bodyHtml, opts) -> { win, dom, opened, copied }
   opts: title, url, clipboard (false to omit navigator.clipboard), prompt (prompt() return
   value), syncTimers (false to keep real setTimeout), setup(win) (extra stubbing before run). */
function loadScript(jsPath, bodyHtml, opts) {
  opts = opts || {};
  const dom = new JSDOM(
    '<!doctype html><html><head><title>' + (opts.title || 'T') + '</title></head><body>'
      + (bodyHtml || '') + '</body></html>',
    { runScripts: 'outside-only', url: opts.url || 'https://site.example/page' });
  const win = dom.window;
  const opened = [];
  win.open = function (u, n, f) { opened.push([u, n, f]); };
  const copied = [];
  if (opts.clipboard !== false) {
    win.navigator.clipboard = {
      writeText: function (s) { copied.push(s); return Promise.resolve(); },
    };
  }
  if (Object.prototype.hasOwnProperty.call(opts, 'prompt')) {
    win.prompt = function () { return opts.prompt; };
  }
  if (opts.syncTimers !== false) {
    win.setTimeout = function (fn) { fn(); return 0; };   // run deferred callbacks deterministically
  }
  if (opts.setup) { opts.setup(win); }
  const ctx = dom.getInternalVMContext();
  new vm.Script(fs.readFileSync(jsPath, 'utf8'), { filename: jsPath }).runInContext(ctx);
  return { win: win, dom: dom, opened: opened, copied: copied };
}

/* Resolve a covered script's path inside the synced sandbox workdir (roots/<site>/<relpath>). */
function sitePath(site, rel) {
  const path = require('path');
  return path.join(__dirname, '..', 'roots', site, rel);
}

module.exports = { loadScript: loadScript, sitePath: sitePath };
