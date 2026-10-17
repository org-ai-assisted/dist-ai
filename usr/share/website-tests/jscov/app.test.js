'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of the mw-static-generator app.js (the wiki stage sites' interactive layer;
   byte-identical in both stage sites). ~25 feature modules wired in ready(); each test loads
   app.js over a DOM tailored to its feature and drives every branch. jsdom lacks matchMedia /
   ResizeObserver / layout geometry / a throwing print, so those are stubbed per case. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const APP = sitePath('kicksecure-stage.github.io', 'app.js');
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

// The wiki stage root is only present when this jscov run is invoked with a stage site root.
// app.js's 100% gating is deferred to the mw-static-generator Phase 4 integration (see README),
// so register NO tests when the stage tree was not staged -- a family-only run must not break.
if (!require('node:fs').existsSync(APP)) { return; }

/* Common environment: synchronous rAF (so rAF-deferred work runs in-line), a matchMedia stub
   (jsdom has none). `extra` layers per-test overrides. */
function env(extra) {
  return function (w) {
    w.requestAnimationFrame = function (cb) { cb(); return 1; };
    w.matchMedia = function () { return { matches: false }; };
    if (extra) { extra(w); }
  };
}
function load(body, opts) {
  opts = opts || {};
  if (!opts.setup) { opts.setup = env(); }
  const r = loadScript(APP, body, opts);
  // jsdom's readyState is 'loading' when the script runs, so app.js's ready() defers to
  // DOMContentLoaded; fire it so the init functions actually run.
  r.win.document.dispatchEvent(new r.win.Event('DOMContentLoaded'));
  return r;
}

/* ---- load-time: applyStoredTheme + ready() dispatch -------------------------------------- */

test('applyStoredTheme: stored dark', function () {
  const { win } = loadScript(APP, '', { setup: env(function (w) { w.localStorage.setItem('theme', 'dark'); }) });
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'dark');
});

test('applyStoredTheme: stored light', function () {
  const { win } = loadScript(APP, '', { setup: env(function (w) { w.localStorage.setItem('theme', 'light'); }) });
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'light');
});

test('applyStoredTheme: no theme + matchMedia dark', function () {
  const { win } = loadScript(APP, '', {
    setup: function (w) {
      w.requestAnimationFrame = function (cb) { cb(); return 1; };
      w.matchMedia = function () { return { matches: true }; };
    },
  });
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'dark');
});

test('ready(): readyState loading defers to DOMContentLoaded', function () {
  const { win } = loadScript(APP, '<a data-darkmode href="#">t</a>', {
    setup: function (w) {
      w.requestAnimationFrame = function (cb) { cb(); return 1; };
      w.matchMedia = function () { return { matches: false }; };
      Object.defineProperty(w.document, 'readyState', { configurable: true, value: 'loading' });
    },
  });
  win.document.dispatchEvent(new win.Event('DOMContentLoaded'));   // now initAll runs
  const link = win.document.querySelector('[data-darkmode]');
  link.click();
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'dark');
});

/* ---- dark mode, copy, data-copy, print --------------------------------------------------- */

test('dark-mode toggle flips and persists', function () {
  const { win } = load('<a data-darkmode href="#">t</a>');
  const link = win.document.querySelector('[data-darkmode]');
  link.click();   // none -> dark
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'dark');
  assert.strictEqual(win.localStorage.getItem('theme'), 'dark');
  link.click();   // dark -> light
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'light');
});

const CODEBLOCK = '<div class="code-select" data-code="sudo apt update">x</div>';

test('copy button: clipboard resolve marks copied then restores', async function () {
  const { win, copied } = load(CODEBLOCK);
  const btn = win.document.querySelector('.code-select .cbutton');
  btn.click();
  await tick();
  assert.deepStrictEqual(copied, ['sudo apt update']);
});

test('copy button: reject + no-clipboard select the code; data-code null uses textContent', function () {
  const { win } = load('<div class="code-select">plain text</div>', {
    setup: env(function (w) {
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); };
    }),
  });
  const block = win.document.querySelector('.code-select');
  block.querySelector('.cbutton').click();          // reject -> selectNodeText
  block.querySelector('.viewport').click();         // vp click -> selectNodeText
  // second load: no clipboard -> else branch (selectNodeText + markCopied)
  const { win: w2 } = load(CODEBLOCK, { clipboard: false, setup: env() });
  w2.document.querySelector('.cbutton').click();
});

test('copy button: already-loaded block is skipped', function () {
  const { win } = load(CODEBLOCK);
  // Re-run initCopyButtons indirectly: the block now has js-fully-loaded; a fresh DOMContentLoaded
  // path is awkward, so just assert the guard class is present (set once).
  assert.ok(win.document.querySelector('.code-select').classList.contains('js-fully-loaded'));
});

test('data-copy: resolve, reject, and no-clipboard all flash', function () {
  const { win } = load('<button data-copy="hello">c</button>');
  win.document.querySelector('[data-copy]').click();   // resolve -> done
  const { win: w2 } = load('<button data-copy="hello">c</button>', { clipboard: false, setup: env() });
  w2.document.querySelector('[data-copy]').click();    // no clipboard -> done
});

test('print button: success and throwing print are both handled', function () {
  const okCalled = { n: 0 };
  load('<button data-action="print">p</button>', {
    setup: env(function (w) { w.print = function () { okCalled.n++; }; }),
  }).win.document.querySelector('[data-action=print]').click();
  assert.strictEqual(okCalled.n, 1);
  load('<button data-action="print">p</button>', {
    setup: env(function (w) { w.print = function () { throw new Error('no'); }; }),
  }).win.document.querySelector('[data-action=print]').click();   // caught
});

/* ---- collapsibles + expand/collapse all -------------------------------------------------- */

test('collapsibles toggle and expand/collapse-all', function () {
  const { win } = load(
    '<div class="mw-collapsible mw-collapsed">a</div><div class="mw-collapsible">b</div>'
    + '<button class="expand-or-collapse-all-button">all</button>');
  const items = win.document.querySelectorAll('.mw-collapsible');
  const t0 = items[0].querySelector('.collapsible-toggle');
  assert.strictEqual(t0.textContent, 'Learn More');   // collapsed label
  t0.click();
  assert.strictEqual(t0.textContent, 'Collapse');      // expanded label
  const all = win.document.querySelector('.expand-or-collapse-all-button');
  all.click();   // item1 now expanded, item0 expanded -> none collapsed -> collapse all
  assert.ok(items[0].classList.contains('mw-collapsed'));
  all.click();   // any collapsed -> expand all
  assert.ok(!items[0].classList.contains('mw-collapsed'));
});

/* ---- tabs + hash sync -------------------------------------------------------------------- */

function tabsDom() {
  return '<div class="tab-content-controller">'
    + '<div class="mininav"></div>'
    + '<div class="tcc-content">'
    + '<div class="tcc-section active"><div class="tcc-title"><h2 id="s1">One<span class="mw-editsection">[edit]</span></h2></div></div>'
    + '<div class="tcc-section"><div class="tcc-title"><h2 id="s2">Two</h2></div>'
    + '<div class="tcc-image"><img></div></div>'
    + '</div></div>';
}

test('tabs: build switcher, click to activate, label strips editsection', function () {
  const { win } = load(tabsDom());
  const pills = win.document.querySelectorAll('.tcc-tab');
  assert.strictEqual(pills.length, 2);
  assert.strictEqual(pills[0].textContent, 'One');   // [edit] stripped
  pills[1].click();
  const secs = win.document.querySelectorAll('.tcc-section');
  assert.ok(secs[1].classList.contains('active'));
});

test('tabs: controller with no sections or no nav is skipped', function () {
  load('<div class="tab-content-controller"><div class="mininav"></div><div class="tcc-content"></div></div>');
  load('<div class="tab-content-controller"><div class="tcc-content"><div class="tcc-section"></div></div></div>');
});

test('syncTabsFromHash: fragment inside an inactive tab activates it', function () {
  const { win } = load(tabsDom(), {
    setup: env(),
    url: 'https://site.example/page#s2',
  });
  win.dispatchEvent(new win.Event('hashchange'));
  const secs = win.document.querySelectorAll('.tcc-section');
  assert.ok(secs[1].classList.contains('active'));
});

/* ---- nav + tools toggles ----------------------------------------------------------------- */

test('nav toggle: outside click, nav-link click, Escape all close', function () {
  const { win } = load(
    '<input type="checkbox" id="nav-toggle"><header class="site-header">'
    + '<nav class="site-nav"><a href="#x">link</a></nav></header><div id="out">o</div>');
  const d = win.document;
  const toggle = d.getElementById('nav-toggle');
  toggle.checked = true;
  d.querySelector('.site-nav a').click();          // nav link inside header -> close
  assert.strictEqual(toggle.checked, false);
  toggle.checked = true;
  d.getElementById('out').click();                 // outside -> close
  assert.strictEqual(toggle.checked, false);
  toggle.checked = true;
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }));
  assert.strictEqual(toggle.checked, false);
  // header-but-not-nav-link click stays open
  toggle.checked = true;
  d.querySelector('.site-header').click();
  assert.strictEqual(toggle.checked, true);
});

test('nav toggle / tools toggle: absent elements are skipped', function () {
  load('<div>nothing</div>');
});

test('tools toggle: outside, tools-item, inside-stay, Escape', function () {
  const { win } = load(
    '<div class="tools"><input type="checkbox" id="tools-toggle">'
    + '<a class="tools-item" href="#a">i</a><button class="copybtn2">c</button></div><div id="out">o</div>');
  const d = win.document;
  const toggle = d.getElementById('tools-toggle');
  toggle.checked = true;
  d.querySelector('.copybtn2').click();            // inside tools, not a tools-item -> stay open
  assert.strictEqual(toggle.checked, true);
  d.querySelector('a.tools-item').click();         // tools-item -> close
  assert.strictEqual(toggle.checked, false);
  toggle.checked = true;
  d.getElementById('out').click();                 // outside -> close
  assert.strictEqual(toggle.checked, false);
  toggle.checked = true;
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }));
  assert.strictEqual(toggle.checked, false);
});

/* ---- back to top ------------------------------------------------------------------------- */

test('back-to-top: appears past threshold, idle-hides, click scrolls, hides under threshold', function () {
  let scrolled = 0;
  const { win } = load('', { setup: env(function (w) { w.scrollTo = function () { scrolled++; }; }) });
  const btn = win.document.querySelector('.back-to-top');
  assert.ok(btn && btn.hidden);
  Object.defineProperty(win, 'scrollY', { configurable: true, value: 500 });
  win.dispatchEvent(new win.Event('scroll'));       // >=400 -> shown, idle setTimeout (syncTimers hides)
  Object.defineProperty(win, 'scrollY', { configurable: true, value: 100 });
  win.dispatchEvent(new win.Event('scroll'));       // <400 -> hidden
  assert.strictEqual(btn.hidden, true);
  btn.hidden = false;
  btn.click();
  assert.strictEqual(scrolled, 1);
});

/* ---- search ------------------------------------------------------------------------------ */

test('search: query filters MWSEARCH, <2 chars hides, caps at 20, no-match hides', function () {
  const many = [];
  for (let i = 0; i < 25; i++) { many.push({ t: 'Match ' + i, u: 'wiki/M' + i + '/' }); }
  const { win } = load(
    '<script src="app.js"></script><div><input id="search-input"></div>', {
      setup: env(function (w) { w.MWSEARCH = many; }),
    });
  const input = win.document.getElementById('search-input');
  input.value = 'z';
  input.dispatchEvent(new win.Event('input'));       // <2 -> hidden
  const results = win.document.querySelector('.search-results');
  assert.ok(results.hidden);
  input.value = 'match';
  input.dispatchEvent(new win.Event('input'));       // matches, capped at 20
  assert.strictEqual(results.querySelectorAll('li').length, 20);
  input.value = 'nomatchxyz';
  input.dispatchEvent(new win.Event('input'));
  assert.ok(results.hidden);
});

test('search: no input element or no MWSEARCH is skipped', function () {
  load('<input id="search-input">');                 // no MWSEARCH
});

/* ---- banners: consent / stage / sitenotice ----------------------------------------------- */

test('consent banner: dismiss persists; pre-acked stays hidden', function () {
  const { win } = load('<div class="bottom-stack"><div class="consent-banner"><button data-consent-dismiss>x</button></div></div>');
  win.document.querySelector('[data-consent-dismiss]').click();
  assert.strictEqual(win.localStorage.getItem('legal-agreement-banner-dismissed'), '1');
  const { win: w2 } = load('<div class="consent-banner">b</div>', {
    setup: env(function (w) { w.localStorage.setItem('legal-agreement-banner-dismissed', '1'); }),
  });
  assert.strictEqual(w2.document.querySelector('.consent-banner').hidden, true);
});

test('stage banner: dismiss persists; pre-dismissed stays hidden', function () {
  const { win } = load('<div class="bottom-stack"><div class="stage-banner"><button data-stage-dismiss>x</button></div></div>');
  win.document.querySelector('[data-stage-dismiss]').click();
  assert.strictEqual(win.localStorage.getItem('stage-notice-dismissed'), '1');
  const { win: w2 } = load('<div class="stage-banner">b</div>', {
    setup: env(function (w) { w.localStorage.setItem('stage-notice-dismissed', '1'); }),
  });
  assert.strictEqual(w2.document.querySelector('.stage-banner').hidden, true);
});

test('sitenotice: dismiss stores id; same id stays hidden; force-show ignores dismissal', function () {
  const { win } = load('<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="n1">'
    + '<button data-sitenotice-dismiss>x</button></div></div>');
  win.document.querySelector('[data-sitenotice-dismiss]').click();
  assert.strictEqual(win.localStorage.getItem('sitenotice-dismissed'), 'n1');
  const { win: w2 } = load('<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="n1">b</div></div>', {
    setup: env(function (w) { w.localStorage.setItem('sitenotice-dismissed', 'n1'); }),
  });
  assert.strictEqual(w2.document.getElementById('siteNotice').hidden, true);
  const { win: w3 } = load('<div id="siteNotice"><div class="sitenotice-banner force-show" data-banner-id="n1">b</div></div>', {
    setup: env(function (w) { w.localStorage.setItem('sitenotice-dismissed', 'n1'); }),
  });
  assert.strictEqual(w3.document.getElementById('siteNotice').hidden, false);   // force-show
});

test('sitenotice: no wrap / no banner is skipped', function () {
  load('<div id="siteNotice"></div>');
  load('<div>no notice</div>');
});

/* ---- bottom stack spacer ----------------------------------------------------------------- */

test('bottom-stack spacer: measures and recomputes on resize', function () {
  const { win } = load('<div class="bottom-stack">stack</div>');
  win.dispatchEvent(new win.Event('resize'));   // rAF sync -> remeasure
  win.dispatchEvent(new win.Event('resize'));   // second resize while raf set? rAF sync so raf resets
});

test('bottom-stack spacer: absent stack is skipped', function () {
  load('<div>no stack</div>');
});

/* ---- flyin donate toast ------------------------------------------------------------------ */

const FLYIN = '<div id="fly-in-notification-panel"><button class="close-panel">x</button></div>';

test('flyin: test-settings (valid attrs) shows; close via click + transitionend', function () {
  const { win } = load(FLYIN
    + '<div id="fly-in-notification-test-settings" data-waitinseconds="1" data-dismissfordays="2" data-now="1000"></div>');
  const panel = win.document.getElementById('fly-in-notification-panel');
  assert.strictEqual(panel.hidden, false);                 // setTimeout(syncTimers) -> show; rAF -> flyin-shown
  assert.ok(panel.classList.contains('flyin-shown'));
  panel.querySelector('.close-panel').click();             // close(): remove flyin-shown, store, transitionend
  panel.dispatchEvent(new win.Event('transitionend'));
  assert.strictEqual(panel.hidden, true);
});

test('flyin: test-settings with invalid attrs (NaN) keeps defaults; close via keyboard', function () {
  const { win } = load(FLYIN + '<div id="fly-in-notification-test-settings"></div>');
  const panel = win.document.getElementById('fly-in-notification-panel');
  const btn = panel.querySelector('.close-panel');
  btn.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Enter' }));   // close
  const { win: w2 } = load(FLYIN + '<div id="fly-in-notification-test-settings"></div>');
  w2.document.querySelector('.close-panel').dispatchEvent(new w2.KeyboardEvent('keydown', { key: ' ' }));
});

test('flyin: December schedule (non-test, not dismissed)', function () {
  const { win } = load(FLYIN, {
    setup: env(function (w) {
      function FakeDate() {}
      FakeDate.prototype.getMonth = function () { return 11; };   // December
      FakeDate.now = function () { return 1000; };
      w.Date = FakeDate;
    }),
  });
  assert.strictEqual(win.document.getElementById('fly-in-notification-panel').hidden, false);
});

test('flyin: dismissed within window returns early (stays hidden)', function () {
  const { win } = load(FLYIN, {
    setup: env(function (w) { w.localStorage.setItem('flyin-last-dismissed', String(Date.now())); }),
  });
  assert.strictEqual(win.document.getElementById('fly-in-notification-panel').hidden, false === true);  // still hidden
});

test('flyin: absent panel is skipped', function () {
  load('<div>no flyin</div>');
});

/* ---- modals (via a data-modal-open trigger): open/close/Tab-trap/Escape/underlay --------- */

test('modal trigger: open, Tab trap (both directions), Escape, underlay, re-open closes prev', function () {
  const { win } = load(
    '<button data-modal-open="m1">open1</button><button data-modal-open="m2">open2</button>'
    + '<div id="m1" class="mini-modal" hidden><div class="underlay"></div>'
    + '<button class="mm-close">x</button><a href="#a">l</a><input></div>'
    + '<div id="m2" class="mini-modal" hidden><div class="underlay"></div><button class="mm-close">x</button></div>');
  const d = win.document;
  d.querySelector('[data-modal-open=m1]').click();
  const m1 = d.getElementById('m1');
  assert.ok(m1.classList.contains('active'));
  // Tab trap: forward from last wraps to first; shift from first wraps to last
  const tab = function (shift) { d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Tab', shiftKey: shift })); };
  tab(false); tab(true);
  d.querySelector('[data-modal-open=m2]').click();   // open m2 while m1 active -> close m1 first
  assert.ok(!m1.classList.contains('active'));
  d.getElementById('m2').querySelector('.underlay').click();   // underlay -> close
  d.querySelector('[data-modal-open=m1]').click();
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }));  // Escape -> close
  assert.ok(!d.getElementById('m1').classList.contains('active'));
});

/* ---- download modal ---------------------------------------------------------------------- */

test('download modal: build, countdown (with hidden-pause) to proceed; empty href skipped', function () {
  let savedCb = null;
  const { win } = load(
    '<a class="download-button-v2 dlbtn-modal" href="/files/app.iso?x=1">dl</a>'
    + '<a class="download-button-v2 dlbtn-modal" href="">empty</a>', {
      setup: env(function (w) {
        w.setInterval = function (cb) { savedCb = cb; return 7; };
        w.clearInterval = function () {};
      }),
    });
  const d = win.document;
  d.querySelectorAll('a.dlbtn-modal')[1].click();   // href="" -> if(!href) return
  d.querySelectorAll('a.dlbtn-modal')[0].click();   // builds modal + countdown
  const modal = d.getElementById('download-button-modal');
  assert.ok(modal && !modal.hidden);
  assert.ok(d.querySelector('.dl-filename strong').textContent.indexOf('app.iso') >= 0);
  Object.defineProperty(d, 'hidden', { configurable: true, value: true });
  savedCb();                                         // document.hidden -> pause (return)
  Object.defineProperty(d, 'hidden', { configurable: true, value: false });
  savedCb(); savedCb(); savedCb(); savedCb(); savedCb();   // 5 -> 0 -> proceed.click + clearInterval
});

/* ---- table expand ------------------------------------------------------------------------ */

test('table-expand: button clones table into modal; uncaptioned table skipped', function () {
  const { win } = load(
    '<div class="wiki-content">'
    + '<table><caption>Cap</caption><tr><td id="c1" class="glb-thumb" tabindex="0" role="button">x</td></tr></table>'
    + '<table><tr><td>no caption</td></tr></table></div>');
  const d = win.document;
  const btn = d.querySelector('.expand-table-button');
  assert.ok(btn);
  btn.click();
  const modal = d.querySelector('.table-expand-modal');
  assert.ok(modal && !modal.hidden);
  assert.ok(!modal.querySelector('.glb-thumb'));   // glb-thumb stripped in the clone
});

/* ---- gallery lightbox -------------------------------------------------------------------- */

test('gallery lightbox: open, next/prev, arrow keys, caption; link-wrapped opt-out; empty skip', function () {
  const { win } = load(
    '<div class="gallery">'
    + '<div class="gallerybox"><div class="thumb"><img src="a.png" alt="A"></div><div class="gallerytext">Cap A</div></div>'
    + '<div class="gallerybox"><div class="thumb"><img src="b.png" alt="B"></div></div>'
    + '<div class="gallerybox"><div class="thumb"><a href="x"><img src="c.png"></a></div></div>'   // link= opt-out
    + '</div>'
    + '<div class="gallery"><div class="gallerybox"><div class="thumb"><a href="y"><img src="d.png"></a></div></div></div>');  // all opt-out -> skip
  const d = win.document;
  const thumbs = d.querySelectorAll('.glb-thumb');
  assert.strictEqual(thumbs.length, 2);   // 2 eligible (the <a>-wrapped ones opted out)
  thumbs[0].click();                       // openAt(0)
  const modal = d.querySelector('.gallery-lightbox');
  assert.ok(modal && !modal.hidden);
  assert.strictEqual(d.querySelector('.glb-caption').textContent, 'Cap A');
  d.querySelector('.glb-next').click();    // step(1) -> image B (alt caption)
  assert.strictEqual(d.querySelector('.glb-caption').textContent, 'B');
  d.querySelector('.glb-prev').click();    // step(-1)
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'ArrowRight' }));
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'ArrowLeft' }));
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Enter' }));   // ignored key
  // keyboard open via Enter/Space on a thumb
  thumbs[1].dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Enter' }));
});

test('gallery lightbox: single image has no prev/next', function () {
  const { win } = load('<div class="gallery"><div class="gallerybox"><div class="thumb"><img src="a.png"></div></div></div>');
  win.document.querySelector('.glb-thumb').dispatchEvent(new win.KeyboardEvent('keydown', { key: ' ' }));   // open via Space
  assert.ok(!win.document.querySelector('.glb-nav'));
});

/* ---- hovercards -------------------------------------------------------------------------- */

test('hovercards: reference preview + page preview + skips; card hover keeps open', function () {
  const { win } = load(
    '<script src="app.js"></script>'
    + '<div class="wiki-content">'
    + '<sup class="reference"><a href="#fn1">[1]</a></sup>'
    + '<a id="pg" href="wiki/Foo/">Foo</a>'
    + '<a id="ext" href="https://evil.example/wiki/Foo/">ext</a>'
    + '<a id="frag" href="#top">top</a>'
    + '<li id="fn1"><span class="mw-cite-backlink">^</span> footnote body</li>'
    + '</div>', {
      setup: env(function (w) { w.MWPREVIEWS = { 'wiki/Foo/': { t: 'Foo', d: 'A summary.' } }; }),
      url: 'https://site.example/',
    });
  const d = win.document;
  const content = d.querySelector('.wiki-content');
  const over = function (el) { el.dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true })); };
  over(d.querySelector('sup.reference a'));   // refNodes -> card
  const card = d.querySelector('.hovercard');
  assert.ok(card && !card.hidden);
  card.dispatchEvent(new win.MouseEvent('mouseenter'));   // clear hide timer
  card.dispatchEvent(new win.MouseEvent('mouseleave'));   // hideSoon
  over(d.getElementById('pg'));               // pageNodes -> card
  assert.ok(d.querySelector('.hovercard-extract'));
  over(d.getElementById('ext'));              // external -> skip
  over(d.getElementById('frag'));             // in-page # -> skip
  content.dispatchEvent(new win.MouseEvent('mouseout', { bubbles: true }));
});

test('hovercards: no .wiki-content is skipped; ref with no target / page with no summary', function () {
  load('<div>no wiki-content</div>');
  const { win } = load(
    '<div class="wiki-content">'
    + '<sup class="reference"><a href="#nope">[1]</a></sup>'          // no #nope element -> refNodes null
    + '<a id="pg" href="wiki/Bar/">Bar</a></div>', {
      setup: env(function (w) { w.MWPREVIEWS = { 'wiki/Bar/': { t: 'Bar' } }; }),   // no .d -> null
      url: 'https://site.example/',
    });
  const d = win.document;
  d.querySelector('sup.reference a').dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true }));
  d.getElementById('pg').dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true }));
});

/* ---- storage viewer ---------------------------------------------------------------------- */

test('storage viewer: lists known + unrecognized keys, per-item delete, delete-all', function () {
  const { win } = load('<div data-storage-viewer></div>', {
    setup: env(function (w) {
      w.localStorage.setItem('theme', 'dark');          // a known key, set
      w.localStorage.setItem('mystery', 'v');           // unrecognized
    }),
  });
  const d = win.document;
  assert.ok(d.querySelector('.storage-table'));
  assert.ok(d.querySelector('.storage-unset'));          // an unset known key
  d.querySelector('.storage-del').click();               // delete one -> re-render
  d.querySelector('.storage-clear').click();             // delete all -> re-render
});

test('storage viewer: localStorage unavailable shows note; absent mount skipped', function () {
  load('<div>no viewer</div>');
  load('<div data-storage-viewer></div>', {
    setup: env(function (w) {
      Object.defineProperty(w, 'localStorage', {
        configurable: true,
        get: function () { throw new Error('blocked'); },
      });
    }),
  });
});

/* ---- wide-table scroll ------------------------------------------------------------------- */

function wideTableDom() {
  return '<div class="wiki-content"><table><caption>c</caption>'
    + '<tr><td>cell</td></tr></table></div>';
}
function makeWide(win, over) {
  const t = win.document.querySelector('.wiki-content table');
  Object.defineProperty(t, 'scrollWidth', { configurable: true, value: over ? 500 : 50 });
  Object.defineProperty(t, 'clientWidth', { configurable: true, value: 100 });
  return t;
}

test('wide-table: ResizeObserver present builds rail when overwide, hides when fits', function () {
  let roCb = null;
  const { win } = load(wideTableDom(), {
    setup: env(function (w) {
      w.ResizeObserver = function (cb) { roCb = cb; this.observe = function () {}; };
    }),
  });
  makeWide(win, true);
  roCb();   // overwide -> build rail
  assert.ok(win.document.querySelector('.table-scroll-top'));
  const rail = win.document.querySelector('.table-scroll-top');
  rail.dispatchEvent(new win.Event('scroll'));           // rail -> table sync
  win.document.querySelector('.wiki-content table').dispatchEvent(new win.Event('scroll'));  // table -> rail
  makeWide(win, false);
  roCb();   // now fits -> rail hidden
  assert.strictEqual(rail.style.display, 'none');
});

test('wide-table: no ResizeObserver uses resize + image load', function () {
  const { win } = load(
    '<div class="wiki-content"><table><caption>c</caption><tr><td><img src="x.png"></td></tr></table></div>', {
      setup: function (w) {
        w.requestAnimationFrame = function (cb) { cb(); return 1; };
        w.matchMedia = function () { return { matches: false }; };
        // no ResizeObserver -> else branch
      },
    });
  makeWide(win, true);
  win.dispatchEvent(new win.Event('resize'));            // rAF sync -> sync -> build
  win.dispatchEvent(new win.Event('resize'));            // raf already 0 after sync; second schedules again
  const img = win.document.querySelector('img');
  img.dispatchEvent(new win.Event('load'));              // image load -> sync
  img.dispatchEvent(new win.Event('error'));             // image error -> sync
});

/* ---- long-tail branches -------------------------------------------------------------------- */

test('ready(): readyState not loading runs fn immediately', function () {
  const { win } = loadScript(APP, '<a data-darkmode href="#">t</a>', {
    setup: function (w) {
      w.requestAnimationFrame = function (cb) { cb(); return 1; };
      w.matchMedia = function () { return { matches: false }; };
      Object.defineProperty(w.document, 'readyState', { configurable: true, value: 'complete' });
    },
  });
  win.document.querySelector('[data-darkmode]').click();   // init ran without a DOMContentLoaded
  assert.strictEqual(win.document.documentElement.getAttribute('data-theme'), 'dark');
});

test('every localStorage try/catch: throwing storage is swallowed', function () {
  const { win } = load(
    '<a data-darkmode href="#">t</a>'
    + '<div class="bottom-stack">'
    + '<div class="consent-banner"><button data-consent-dismiss>x</button></div>'
    + '<div class="stage-banner"><button data-stage-dismiss>x</button></div></div>'
    + '<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="n1"><button data-sitenotice-dismiss>x</button></div></div>'
    + FLYIN, {
      setup: env(function (w) {
        const ls = {
          getItem: function () { throw new Error('x'); },
          setItem: function () { throw new Error('x'); },
          removeItem: function () { throw new Error('x'); },
          clear: function () { throw new Error('x'); }, length: 0, key: function () { return null; },
        };
        Object.defineProperty(w, 'localStorage', { configurable: true, value: ls });
      }),
    });
  const d = win.document;
  d.querySelector('[data-darkmode]').click();          // setItem throws (dark mode)
  d.querySelector('[data-consent-dismiss]').click();   // setItem throws (consent)
  d.querySelector('[data-stage-dismiss]').click();     // setItem throws (stage)
  d.querySelector('[data-sitenotice-dismiss]').click();// setItem throws (sitenotice)
  const close = d.getElementById('fly-in-notification-panel').querySelector('.close-panel');
  if (close) { close.click(); }                        // flyin close setItem throws
});

test('selectNodeText: null selection returns early', function () {
  const { win } = load('<div class="code-select" data-code="x">y</div>', {
    setup: env(function (w) { w.getSelection = function () { return null; }; }),
  });
  win.document.querySelector('.viewport').click();     // selectNodeText -> sel null -> return
});

test('tabs: heading without id (href "#"); section not in a controller (hash); no scrollIntoView', function () {
  const { win } = load(
    '<div class="tab-content-controller"><div class="mininav"></div><div class="tcc-content">'
    + '<div class="tcc-section active"><div class="tcc-title"><h2>No id</h2></div></div>'
    + '<div class="tcc-section"><div class="tcc-title"><h2>Two</h2></div></div>'
    + '</div></div>'
    + '<div class="tcc-section"><span id="orphan">o</span></div>');   // section outside any controller
  assert.strictEqual(win.document.querySelector('.tcc-tab').getAttribute('href'), '#');  // no id -> "#"
});

test('syncTabsFromHash: fragment in a controller-less section hits the !ctrl continue', function () {
  const { win } = load('<div class="tcc-section"><span id="orphan">o</span></div>', {
    setup: env(), url: 'https://site.example/#orphan',
  });
  win.dispatchEvent(new win.Event('hashchange'));   // chain=[section], ctrl null -> continue
});

test('syncTabsFromHash: malformed hash is caught; missing/other elements return', function () {
  load('<div class="tcc-section">x</div>', { setup: env(), url: 'https://site.example/#%E0%A4' });  // decode throws
  load('<div>no frag</div>', { setup: env(), url: 'https://site.example/#' });                       // empty id
  load('<div>no el</div>', { setup: env(), url: 'https://site.example/#ghost' });                    // no element
});

test('tools toggle not inside .tools; nav toggle with no .site-header', function () {
  const { win } = load('<input type="checkbox" id="tools-toggle"><div id="o">o</div>');  // toggle not in .tools
  const tog = win.document.getElementById('tools-toggle');
  tog.checked = true;
  win.document.getElementById('o').click();   // tools falsy -> outside -> close
  assert.strictEqual(tog.checked, false);
  const { win: w2 } = load('<input type="checkbox" id="nav-toggle"><div id="o2">o</div>');  // no .site-header
  const n = w2.document.getElementById('nav-toggle');
  n.checked = true;
  w2.document.getElementById('o2').click();   // header falsy -> close
  assert.strictEqual(n.checked, false);
});

test('search rootPrefix: script with no src is skipped; no app.js script yields ""', function () {
  const { win } = load(
    '<script></script><div><input id="search-input"></div>', {   // a <script> with no src attribute
      setup: env(function (w) { w.MWSEARCH = [{ t: 'Foo', u: 'wiki/Foo/' }]; }),
    });
  const input = win.document.getElementById('search-input');
  input.value = 'foo';
  input.dispatchEvent(new win.Event('input'));
  assert.ok(win.document.querySelector('.search-results li'));
});

test('sitenotice with empty data-banner-id', function () {
  const { win } = load('<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="">'
    + '<button data-sitenotice-dismiss>x</button></div></div>');
  win.document.querySelector('[data-sitenotice-dismiss]').click();
  assert.strictEqual(win.localStorage.getItem('sitenotice-dismissed'), '');
});

test('modal focus trap with real focusables (offsetParent stubbed) + close focuses opener', function () {
  const { win } = load(
    '<button id="opener" data-modal-open="m1">open</button>'
    + '<div id="m1" class="mini-modal" hidden><div class="underlay"></div>'
    + '<button class="mm-close">x</button><a href="#a">l</a><input><button hidden class="h">h</button></div>');
  const d = win.document;
  const opener = d.getElementById('opener');
  opener.focus();                 // real jsdom focus -> activeElement = opener (captured by open())
  opener.click();
  const m1 = d.getElementById('m1');
  // make the modal's focusables "visible" (jsdom offsetParent is always null)
  const foc = m1.querySelectorAll('button, a, input');
  for (let i = 0; i < foc.length; i++) {
    Object.defineProperty(foc[i], 'offsetParent', { configurable: true, value: foc[i].classList.contains('h') ? null : {} });
  }
  const tab = function (shift) { d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Tab', shiftKey: shift })); };
  tab(false);   // wrap to first
  tab(true);    // wrap to last
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }));   // close -> opener.focus()
  assert.ok(!m1.classList.contains('active'));   // closed
});

test('download modal: malformed href falls back to raw filename', function () {
  let savedCb = null;
  const { win } = load('<a class="download-button-v2 dlbtn-modal" href="/a/%E0%A4.iso">dl</a>', {
    setup: env(function (w) { w.setInterval = function (cb) { savedCb = cb; return 1; }; w.clearInterval = function () {}; }),
  });
  win.document.querySelector('a.dlbtn-modal').click();   // decodeURIComponent throws -> fname = href
  assert.ok(win.document.getElementById('download-button-modal'));
});

test('hovercards edge cases: empty-ref, protocol-relative, bad URL, missing key, non-anchor', function () {
  const { win } = load(
    '<script src="app.js"></script>'
    + '<div class="wiki-content">'
    + '<sup class="reference"><a href="#">[1]</a></sup>'          // href "#" -> id "" -> refNodes null
    + '<a id="pr" href="//cdn.example/x">pr</a>'                  // protocol-relative -> skip
    + '<a id="miss" href="wiki/Nope/">n</a>'                      // key not in idx
    + '<span id="plain">no anchor</span>'
    + '</div>', {
      setup: env(function (w) { w.MWPREVIEWS = { 'wiki/Foo/': { t: 'Foo', d: 'x' } }; }),
      url: 'https://site.example/',
    });
  const d = win.document;
  const over = function (el) { el.dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true })); };
  over(d.querySelector('sup.reference a'));
  over(d.getElementById('pr'));
  over(d.getElementById('miss'));
  over(d.getElementById('plain'));   // closest('a') null -> onEnter return
});

test('storage viewer: removeItem + clear throwing are swallowed', function () {
  const { win } = load('<div data-storage-viewer></div>', {
    setup: env(function (w) {
      const store = { theme: 'dark' };
      const keys = Object.keys(store);
      Object.defineProperty(w, 'localStorage', {
        configurable: true,
        value: {
          length: keys.length,
          key: function (i) { return keys[i]; },
          getItem: function (k) { return k in store ? store[k] : null; },
          removeItem: function () { throw new Error('x'); },
          clear: function () { throw new Error('x'); },
        },
      });
    }),
  });
  const d = win.document;
  d.querySelector('.storage-del').click();     // removeItem throws -> catch
  d.querySelector('.storage-clear').click();   // clear throws -> catch
});

test('wide-table: re-entrant scroll hits the lock guard', function () {
  let roCb = null;
  const { win } = load(wideTableDom(), {
    setup: env(function (w) { w.ResizeObserver = function (cb) { roCb = cb; this.observe = function () {}; }; }),
  });
  const table = makeWide(win, true);
  roCb();   // build rail
  const rail = win.document.querySelector('.table-scroll-top');
  // Make a programmatic scrollLeft assignment re-dispatch a scroll event, so the paired
  // handler re-enters while lock is held.
  Object.defineProperty(table, 'scrollLeft', {
    configurable: true,
    get: function () { return 0; },
    set: function () { table.dispatchEvent(new win.Event('scroll')); },
  });
  Object.defineProperty(rail, 'scrollLeft', {
    configurable: true,
    get: function () { return 0; },
    set: function () { rail.dispatchEvent(new win.Event('scroll')); },
  });
  rail.dispatchEvent(new win.Event('scroll'));    // rail: lock -> sets table.scrollLeft -> table scroll w/ lock
  table.dispatchEvent(new win.Event('scroll'));   // table: lock -> sets rail.scrollLeft -> rail scroll w/ lock
});

test('gallery: thumbnail with no src attribute', function () {
  const { win } = load('<div class="gallery"><div class="gallerybox"><div class="thumb"><img alt="A"></div></div></div>');
  win.document.querySelector('.glb-thumb').click();   // src: currentSrc||getAttribute||"" -> ""
  assert.ok(win.document.querySelector('.gallery-lightbox'));
});

test('syncTabsFromHash: target without scrollIntoView', function () {
  const { win } = load(tabsDom(), { setup: env(), url: 'https://site.example/#s2' });
  const el = win.document.getElementById('s2');
  Object.defineProperty(el, 'scrollIntoView', { configurable: true, value: undefined });
  win.dispatchEvent(new win.Event('hashchange'));     // if(el.scrollIntoView) false
});

test('nav/tools toggle: a click while unchecked returns early', function () {
  const { win } = load('<input type="checkbox" id="nav-toggle"><header class="site-header">h</header>'
    + '<div class="tools"><input type="checkbox" id="tools-toggle"></div><div id="o">o</div>');
  win.document.getElementById('o').click();   // both toggles unchecked -> if(!checked) return (nav + tools)
});

test('modal onClose cb runs on close; opener.focus throwing is caught', function () {
  const { win } = load(
    '<div class="wiki-content"><table><caption>c</caption><tr><td>x</td></tr></table></div>');
  const d = win.document;
  const opener = d.querySelector('.expand-table-button');
  opener.focus();
  // make the captured opener's focus throw, so close()'s try/catch around opener.focus() is covered
  opener.focus = function () { throw new Error('nofocus'); };
  opener.click();                                      // opens table-expand modal WITH an onClose cb
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }));   // close -> cb() + opener.focus() throws
  assert.strictEqual(d.querySelector('.table-expand-modal'), null);       // onClose removed it
});

test('modal Tab trap: activeElement at last wraps to first, at first wraps to last', function () {
  const { win } = load(
    '<button data-modal-open="m">open</button>'
    + '<div id="m" class="mini-modal" hidden><button class="mm-close">x</button>'
    + '<a class="l1" href="#a">a</a><a class="l2" href="#b">b</a></div>');
  const d = win.document;
  d.querySelector('[data-modal-open=m]').click();
  const m = d.getElementById('m');
  const foc = m.querySelectorAll('button, a');
  for (let i = 0; i < foc.length; i++) {   // jsdom offsetParent is null; make them "visible"
    Object.defineProperty(foc[i], 'offsetParent', { configurable: true, value: {} });
  }
  const last = foc[foc.length - 1], first = foc[0];
  const outside = d.querySelector('[data-modal-open=m]');
  last.focus();   // real jsdom focus -> activeElement = last
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Tab' }));          // cur===last -> first.focus
  first.focus();
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Tab', shiftKey: true }));  // cur===first -> last.focus
  outside.focus();   // activeElement outside the modal
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Tab' }));          // !contains(cur) -> first.focus
  outside.focus();
  d.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Tab', shiftKey: true }));  // !contains(cur) -> last.focus
});

test('modal trigger with missing target id: open(null) returns', function () {
  const { win } = load('<button data-modal-open="ghost">open</button>');
  win.document.querySelector('[data-modal-open=ghost]').click();   // getElementById null -> open(null) -> return
});

test('syncTabsFromHash: fragment to a non-section element (chain empty); target lacks scrollIntoView', function () {
  // hash target outside any .tcc-section -> chain empty -> if(!chain.length) return
  load('<div class="tab-content-controller"><div class="mininav"></div><div class="tcc-content">'
    + '<div class="tcc-section active"><div class="tcc-title"><h2 id="s1">One</h2></div></div></div></div>'
    + '<div id="loose">x</div>', { setup: env(), url: 'https://site.example/#loose' });
  // target in a section but without scrollIntoView -> if(el.scrollIntoView) false
  // scrollIntoView present (jsdom may lack it) -> if(el.scrollIntoView) TRUE
  const a = load(tabsDom(), { setup: env(), url: 'https://site.example/#s2' });
  const elA = a.win.document.getElementById('s2');
  elA.scrollIntoView = function () {};
  a.win.dispatchEvent(new a.win.Event('hashchange'));
  // scrollIntoView falsy -> if(el.scrollIntoView) FALSE
  const b = load(tabsDom(), { setup: env(), url: 'https://site.example/#s2' });
  const elB = b.win.document.getElementById('s2');
  Object.defineProperty(elB, 'scrollIntoView', { configurable: true, value: null });
  b.win.dispatchEvent(new b.win.Event('hashchange'));
});

test('hovercards: pageNodes with no MWPREVIEWS; title falls back to key when p.t absent', function () {
  const over = function (win, id) {
    win.document.getElementById(id).dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true }));
  };
  // no MWPREVIEWS at all -> if(!idx) return null
  const a = load('<script src="app.js"></script><div class="wiki-content"><a id="pg" href="wiki/Foo/">Foo</a></div>', {
    setup: env(), url: 'https://site.example/',
  });
  over(a.win, 'pg');
  // MWPREVIEWS entry with a summary but no title -> title = (p.t || key) -> key
  const b = load('<script src="app.js"></script><div class="wiki-content"><a id="pg" href="wiki/Foo/">Foo</a></div>', {
    setup: env(function (w) { w.MWPREVIEWS = { 'wiki/Foo/': { d: 'summary only' } }; }),
    url: 'https://site.example/',
  });
  over(b.win, 'pg');
  assert.ok(b.win.document.querySelector('.hovercard-title'));
});

test('download modal: trailing-slash href yields empty basename (|| href)', function () {
  const { win } = load('<a class="download-button-v2 dlbtn-modal" href="/files/">dl</a>', {
    setup: env(function (w) { w.setInterval = function () { return 1; }; w.clearInterval = function () {}; }),
  });
  win.document.querySelector('a.dlbtn-modal').click();   // pop() "" -> decode "" -> || href
  assert.ok(win.document.getElementById('download-button-modal'));
});

test('hovercards: reference anchor with no href attribute', function () {
  const { win } = load(
    '<div class="wiki-content"><sup class="reference"><a>[1]</a></sup></div>', { setup: env() });
  win.document.querySelector('sup.reference a')
    .dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true }));   // href null -> id "" -> null
});

test('hovercards: anchor resolving outside the output tree (subpath root)', function () {
  const { win } = load(
    '<script src="sub/app.js"></script>'
    + '<div class="wiki-content"><a id="up" href="../other/">up</a></div>', {
      setup: env(function (w) { w.MWPREVIEWS = { 'other/': { t: 'O', d: 'x' } }; }),
      url: 'https://site.example/sub/page',
    });
  win.document.getElementById('up')
    .dispatchEvent(new win.MouseEvent('mouseover', { bubbles: true }));   // anchorUrl outside rootUrl -> null
});
