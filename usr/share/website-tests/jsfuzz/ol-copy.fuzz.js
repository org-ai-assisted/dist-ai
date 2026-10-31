'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for the three output-lies copy.js variants (git-diffs-lie/, paste/, and
   git-diffs-lie/all/ -- NOT byte-identical: the comments differ and all/ carries an extra mobile
   nav-toggle IIFE). The copy glue is the clipboard sink: its only attacker/author-influenced input
   is the command textContent it reflects to navigator.clipboard. Invariants assert COPY FIDELITY
   (the clipboard receives the command text byte-for-byte -- no truncation, no transformation, no
   injection of anything the DOM did not contain), that clicking never throws for any command text,
   and that the flash label is set then restored. Curated DOM configs (mirroring the proven jscov
   ol-copy.test.js) drive every branch of each path to deterministic 100% c8 (c8 attributes coverage
   per FILE PATH, so the simple-copy suite is parametrized over all three paths). */

const { fc, test, sitePath, adversarialString } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

/* Every path carries the simple copy IIFE; all/ additionally carries the nav-toggle IIFE. */
const COPY_PATHS = [
  ['git-diffs-lie', sitePath('output-lies.github.io', 'git-diffs-lie/copy.js')],
  ['paste', sitePath('output-lies.github.io', 'paste/copy.js')],
  ['all', sitePath('output-lies.github.io', 'git-diffs-lie/all/copy.js')],
].filter(function (p) { return require('node:fs').existsSync(p[1]); });   // drop sites absent in a partial checkout
const NAV_PATH = sitePath('output-lies.github.io', 'git-diffs-lie/all/copy.js');

const CMD = 'git commit -m ok';
function box(cmdText) {
  /* button ships `hidden` like the real page (progressive enhancement); the IIFE reveals it. */
  return '<div class="copybox"><code class="cmd">' + cmdText + '</code>'
       + '<button class="copybtn" hidden>Copy</button></div>';
}
const EMPTY_BOX = '<div class="copybox"></div>';
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

/* --- simple copy IIFE: every branch on each path, deterministic --- */
function simpleSuite(label, JS) {

  /* !navigator.clipboard TRUE -> IIFE early-returns, no button revealed. */
  test(label + ' copy: no clipboard early-returns', function () {
    const r = loadScript(JS, box(CMD), { clipboard: false });
    /* IIFE bails before btn.hidden=false, so the button stays hidden (not revealed). */
    if (!r.win.document.querySelector('.copybtn').hidden) { throw new Error('no clipboard must leave the button hidden'); }
    if (r.copied.length !== 0) { throw new Error('nothing should be copied without clipboard'); }
  });

  /* !cmd || !btn TRUE (empty box -> no .cmd, no .copybtn) -> that box is skipped. */
  test(label + ' copy: box missing cmd/btn is skipped', function () {
    const r = loadScript(JS, EMPTY_BOX, {});
    if (r.copied.length !== 0) { throw new Error('empty box must not wire a copy'); }
  });

  /* Full box: !clipboard FALSE, !cmd||!btn FALSE -> button revealed; click copies the command,
     the writeText .then flashes 'Copied' then the (sync) setTimeout restores the prior label. */
  test(label + ' copy: click copies command, flashes then restores', async function () {
    const r = loadScript(JS, box(CMD), {});   // syncTimers default -> restore runs synchronously
    const btn = r.win.document.querySelector('.copybtn');
    if (btn.hidden) { throw new Error('button should be revealed'); }
    btn.click();
    await tick();
    if (r.copied.length !== 1 || r.copied[0] !== CMD) {
      throw new Error('clipboard got the wrong text: ' + JSON.stringify(r.copied));
    }
    if (btn.textContent !== 'Copy') { throw new Error('label not restored'); }
    if (btn.classList.contains('ok')) { throw new Error('ok class not cleared'); }
  });

  /* --- invariants --- */

  /* COPY FIDELITY: for ANY command text, clicking copy writes EXACTLY that textContent to the
     clipboard -- the glue never truncates, re-encodes, or injects; the clipboard payload is only
     ever the text the page already displayed. */
  test(label + ' copy: clipboard receives the command text verbatim, never throws', function () {
    fc.assert(fc.property(adversarialString, function (s) {
      let threw = false;
      const r = loadScript(JS, box(''), {});
      const d = r.win.document;
      d.querySelector('.cmd').textContent = s;   // textContent set via DOM API: no markup parsing
      try { d.querySelector('.copybtn').click(); } catch (e) { threw = true; }
      if (threw) { return false; }
      const src = d.querySelector('.cmd').textContent;
      /* exactly one write, equal to the command's current textContent. */
      return r.copied.length === 1 && r.copied[0] === src;
    }), { seed: 1, numRuns: 50 });
  });

  /* FLASH set-then-restore: with the real setTimeout frozen (syncTimers:false), the .then sets the
     label to 'Copied' + ok; the restore is deferred, so the SET state is observable and distinct
     from the captured prior label. */
  test(label + ' copy: flash sets Copied before the deferred restore', async function () {
    const r = loadScript(JS, box(CMD), { syncTimers: false });
    const btn = r.win.document.querySelector('.copybtn');
    btn.click();
    await tick();
    if (btn.textContent !== 'Copied') { throw new Error('flash did not set Copied'); }
    if (!btn.classList.contains('ok')) { throw new Error('flash did not add ok'); }
  });
}

/* --- nav-toggle IIFE (all/copy.js only): every branch --- */
function navSuite(label, JS) {

  /* #navtoggle present: scroll with checked=TRUE closes it (if(nt.checked) TRUE arm); a second
     closeNav via resize runs with checked=false (if(nt.checked) FALSE arm). */
  test(label + ' nav: scroll closes the open toggle, resize is a no-op when closed', function () {
    const r = loadScript(JS, '<input type="checkbox" id="navtoggle">' + box(CMD), {});
    const nt = r.win.document.getElementById('navtoggle');
    nt.checked = true;
    r.win.dispatchEvent(new r.win.Event('scroll'));
    if (nt.checked) { throw new Error('scroll should close the open nav'); }
    r.win.dispatchEvent(new r.win.Event('resize'));   // checked already false -> if(nt.checked) false arm
    if (nt.checked) { throw new Error('resize must not re-open'); }
  });

  /* #navtoggle ABSENT -> if(!nt) return arm. */
  test(label + ' nav: absent toggle early-returns', function () {
    loadScript(JS, box(CMD), {});
  });

  /* INVARIANT: closeNav only ever drives the toggle from checked to unchecked -- it never opens a
     closed nav. For any starting checked state, after scroll+resize the toggle is unchecked. */
  test(label + ' nav: closeNav never opens a closed toggle', function () {
    fc.assert(fc.property(fc.boolean(), function (startChecked) {
      const r = loadScript(JS, '<input type="checkbox" id="navtoggle">' + box(CMD), {});
      const nt = r.win.document.getElementById('navtoggle');
      nt.checked = startChecked;
      r.win.dispatchEvent(new r.win.Event('scroll'));
      r.win.dispatchEvent(new r.win.Event('resize'));
      return nt.checked === false;
    }), { seed: 1, numRuns: 40 });
  });
}

COPY_PATHS.forEach(function (p) { simpleSuite(p[0], p[1]); });
if (require('node:fs').existsSync(NAV_PATH)) { navSuite('all', NAV_PATH); }   // skip when this site is absent
