// Unit + bug-fuzz tests for assets/app.js (the only JS), run with node:test under jsdom.
// CommonJS so `require('jsdom')` resolves the sandbox's GLOBAL jsdom via NODE_PATH (ESM import
// ignores NODE_PATH). app.js is a browser IIFE (no exports): we load it INTO a jsdom window with
// a DOM fixture, fire DOMContentLoaded, then assert behaviour / drive events.
// Run (confined): NODE_PATH="$(npm root -g)" c8 node --test "tools/js-tests/**/*.test.cjs"
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM, VirtualConsole } = require("jsdom");

// Swallow jsdom's "Not implemented" notices (window.print, link navigation from the download
// modal's countdown) -- they are jsdom gaps, not app bugs, and app.js try/catches the real ones.
function quietConsole() {
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { if (!/Not implemented/.test(String(e && e.message))) throw e; });
  return vc;
}

// Dual-run subject resolution. app.js lives in mw-static-generator; this suite is centralized in
// dist-ai (single source), so it resolves the subject two ways:
//  - APP_JS env: the CROSS-REPO invoke from mw-static-generator's gate -- the pretty source, and
//    (built-tree lane) the minified app.min.js, so the WHOLE suite re-runs against served bytes
//    (minifier-integrity). This is app.js's primary commit-time gate.
//  - else: the dist-ai jscov LANE's staged wiki-stage root (belt-and-suspenders, when a stage root
//    is passed). Self-skip if neither resolves, so a partial checkout never throws at load.
const { sitePath } = require("./harness.js");
const APP_JS = process.env.APP_JS
  ? path.resolve(process.env.APP_JS)
  : sitePath("kicksecure-stage.github.io", "app.js");
if (!require("node:fs").existsSync(APP_JS)) { return; }   // no subject -> self-skip (partial checkout / no stage root)
// //# sourceURL names the eval'd script so V8/c8 attribute coverage to app.js (else it is
// unmapped eval code and coverage reads 0/0).
// Raw source; vm.Script's `filename` option (in load()) attributes c8 coverage to app.js -- it
// also attributes the outer IIFE wrapper correctly, which a `w.eval(src + //# sourceURL)` load did
// NOT (the wrapper read 0, a measurement artifact, not dead code). Same loader as jscov/harness.js.
const SRC = readFileSync(APP_JS, "utf8");

// Build a jsdom window with `bodyHtml`, load app.js into it, fire DOMContentLoaded.
// `storage` seeds localStorage BEFORE load (so applyStoredTheme / pre-dismiss paths run).
function load(bodyHtml, opts) {
  opts = opts || {};
  const url = (opts.url || "https://x.test/wiki/Page") + (opts.hash || "");
  // Inert <link rel> carriers for the lazily-fetched search / preview JSON, present whenever a
  // test seeds that payload (mirrors the real head). headExtra injects extra head markup (e.g.
  // the instant.page module script for the rootPrefix look-alike test).
  const carriers =
    (opts.searchIndex !== undefined ? '<link rel="mw-search-index" href="/search-index.min.json">' : "") +
    (opts.previews !== undefined ? '<link rel="mw-page-previews" href="/page-previews.min.json">' : "") +
    (opts.manifest !== undefined ? '<link rel="mw-fulltext-manifest" href="/search/fulltext-manifest.min.json">' : "");
  const dom = new JSDOM(
    `<!doctype html><html class="client-js"><head>` +
    `<script src="` + (opts.appSrc || "../../app.js") + `"></script>` + (opts.headExtra || "") + carriers + `</head>` +
    `<body>${bodyHtml}</body></html>`,
    { url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: quietConsole() });
  const w = dom.window;
  w.matchMedia = w.matchMedia || (() => ({ matches: false, addEventListener() {}, addListener() {} }));
  // Record each ResizeObserver so a test can fire its (batched) callback and inspect targets;
  // observe() still never auto-invokes, so every other test sees the former no-op behaviour.
  if (!w.ResizeObserver) {
    w.__resizeObservers = [];
    w.ResizeObserver = class {
      constructor(cb) { this.cb = cb; this.targets = []; w.__resizeObservers.push(this); }
      observe(t) { this.targets.push(t); }
      unobserve() {} disconnect() {}
    };
  }
  if (!w.IntersectionObserver) w.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
  w.print = () => {};  // jsdom throws "Not implemented" otherwise
  w.scrollTo = () => {};
  // Lazy payloads load via a same-origin fetch (connect-src 'self'); jsdom ships no fetch, so
  // stub it to resolve the seeded JSON. An unseeded URL resolves {ok:false} -> app.js degrades
  // to an empty index (never throws). Matches by basename so the carrier's ?h=/relative form is
  // irrelevant.
  w.fetch = (u) => {
    u = String(u);
    const shard = u.match(/\/ft\/(\d+)\.json/);
    let data;
    if (/fulltext-manifest/.test(u)) data = opts.manifest;
    else if (shard) data = opts.shards && opts.shards[shard[1]];
    else if (/search-index/.test(u)) data = opts.searchIndex;
    else if (/page-previews/.test(u)) data = opts.previews;
    return Promise.resolve({ ok: data != null, json: () => Promise.resolve(data) });
  };
  try { w.localStorage.clear(); } catch (e) {}
  if (opts.storage) for (const k of Object.keys(opts.storage)) {
    try { w.localStorage.setItem(k, opts.storage[k]); } catch (e) {}
  }
  // Last-chance hook to shape the window just before the IIFE runs: used to exercise
  // branches that depend on host state read AT LOAD -- document.readyState (the `ready`
  // immediate path), window.requestIdleCallback (the `whenIdle` deferred path), a December
  // `Date` (the fly-in's month-11 schedule), a throwing localStorage (every storage catch),
  // or the absence of ResizeObserver (the wide-table resize fallback). Seeding has already run.
  if (opts.preEval) opts.preEval(w);
  new vm.Script(SRC, { filename: APP_JS }).runInContext(dom.getInternalVMContext());
  w.document.dispatchEvent(new w.Event("DOMContentLoaded", { bubbles: true }));
  return w;
}

const tick = () => new Promise((r) => setTimeout(r, 5));

// ---- code-select / copy widgets ------------------------------------------------------------

test("code-select is enriched: copy button + viewport + .code, once", () => {
  const w = load('<span class="code-select" data-code="sudo apt update">x</span>');
  const cs = w.document.querySelector(".code-select");
  assert.ok(cs.classList.contains("js-fully-loaded"), "marked js-fully-loaded");
  assert.ok(cs.querySelector(".cbutton"), "has a copy button");
  const code = cs.querySelector(".viewport > .code");
  assert.ok(code, "code is wrapped in a .viewport");
  assert.equal(code.textContent, "sudo apt update", "code text preserved from data-code");
  assert.equal(cs.querySelector(".viewport").getAttribute("tabindex"), "0",
    "viewport is keyboard-focusable so a long value can be scrolled (scrollable-region-focusable)");
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  assert.equal(cs.querySelectorAll(".cbutton").length, 1, "not re-enriched");
});

test("code-select without data-code falls back to its textContent", () => {
  const w = load('<span class="code-select">echo hi</span>');
  assert.equal(w.document.querySelector(".viewport > .code").textContent, "echo hi");
});

test("code-select copy button: clicking marks .copied then clears (fallback path)", () => {
  const w = load('<span class="code-select" data-code="x">x</span>');
  const cs = w.document.querySelector(".code-select");
  cs.querySelector(".cbutton").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.ok(cs.classList.contains("copied"), "flashes copied on click");
});

test("data-copy button flashes .copied on click (no clipboard -> fallback)", () => {
  const w = load('<button data-copy="permalink-url">Permalink</button>');
  const b = w.document.querySelector("[data-copy]");
  b.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.ok(b.classList.contains("copied"));
});

test("share copy-card: logo image button, raw text hidden, copies data-code", () => {
  const w = load('<span class="code-select cs-image" data-social="copy-mediawiki" '
    + 'data-code="[[P|T]]" data-button-image-src="/media/Mediawiki-logo.png.webp">[[P|T]]</span>');
  const cs = w.document.querySelector(".code-select");
  const btn = cs.querySelector(".cbutton");
  const img = btn.querySelector("img.cbutton-img");
  assert.ok(img, "the copy button is a logo <img>, not a glyph");
  assert.equal(img.getAttribute("src"), "/media/Mediawiki-logo.png.webp", "logo src from data-button-image-src");
  assert.ok(!btn.classList.contains("fa-clone"), "no clone glyph on the logo button");
  assert.equal(cs.querySelector(".viewport > .code").textContent, "[[P|T]]", "raw value kept for copy fallback");
  btn.dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.ok(cs.classList.contains("copied"), "flashes copied on click");
  assert.ok(btn.querySelector("img.cbutton-img"), "logo stays after copy (no glyph swap)");
});

test("per-heading share: inert <template> REPLACES the no-JS permalink on first press (no dup), copy wired", () => {
  const w = load(
    '<span class="share-tooltip" data-anchor="Sec">' +
    '<a class="headline-anchor" href="#Sec">s</a>' +
    '<span class="menu-wrapper"><span class="menu">' +
    '<span class="menu-headline">h</span>' +
    '<span class="code-select" data-code="https://x.test/wiki/Page#Sec">p</span>' +
    '<template class="share-full">' +  // the full menu RE-INCLUDES the permalink (as on real pages)
    '<span class="menu-headline">h2</span>' +
    '<span class="code-select" data-code="https://x.test/wiki/Page#Sec">p2</span>' +
    '<span class="share-social"><a href="https://soc.test">x</a></span></template>' +
    "</span></span></span>");
  const tip = w.document.querySelector(".share-tooltip");
  // template content is inert: querySelectorAll does NOT descend into it, so only the permalink
  // code-select is live/enriched at load -- the ~130-node menu costs no DOM/style/layout yet.
  assert.equal(w.document.querySelectorAll(".menu .code-select").length, 1,
    "only the permalink code-select is live before the share is pressed");
  assert.ok(tip.querySelector("template.share-full"), "full section menu is parked in a <template>");
  // first press activates it: the template's full menu (which RE-INCLUDES the permalink) replaces
  // the rendered no-JS permalink, so the direct link is NOT duplicated.
  tip.dispatchEvent(new w.Event("pointerdown", { bubbles: true }));
  assert.ok(!tip.querySelector("template.share-full"), "template is consumed on first press");
  assert.equal(w.document.querySelectorAll(".menu .menu-headline").length, 1,
    "the 'Copy or share this direct link' headline is not duplicated");
  const live = w.document.querySelectorAll(".menu .code-select");
  assert.equal(live.length, 1, "exactly one (deduped) permalink code-select in the live menu");
  assert.ok(live[0].classList.contains("js-fully-loaded"), "the activated copy button is wired");
  assert.ok(tip.querySelector(".share-social"), "the social share row is injected from the template");
  // idempotent: a second press is a no-op (no template left), does not duplicate
  tip.dispatchEvent(new w.Event("pointerdown", { bubbles: true }));
  assert.equal(w.document.querySelectorAll(".menu .code-select").length, 1, "no duplication on re-press");
});

test("per-heading share: HOVER (pointerover) primes the full menu -- no click needed", () => {
  const w = load(
    '<span class="share-tooltip" data-anchor="Sec">' +
    '<a class="headline-anchor" href="#Sec">s</a>' +
    '<span class="menu-wrapper"><span class="menu">' +
    '<span class="code-select" data-code="https://x.test/wiki/Page#Sec">p</span>' +
    '<template class="share-full">' +
    '<span class="menu-headline">h2</span>' +
    '<span class="share-social"><a href="https://soc.test">x</a></span></template>' +
    "</span></span></span>");
  const tip = w.document.querySelector(".share-tooltip");
  assert.ok(tip.querySelector("template.share-full"), "menu parked in <template> at load");
  // Hover ALONE (no press/click) must inject the full menu so CSS :hover reveals it (desktop
  // hover-to-open). Regression: priming was gated on pointerdown, so hover showed only the
  // pre-rendered permalink and a click was required to expand.
  tip.querySelector(".headline-anchor").dispatchEvent(new w.Event("pointerover", { bubbles: true }));
  assert.ok(!tip.querySelector("template.share-full"), "hover consumes the template (full menu injected, no click)");
  assert.ok(tip.querySelector(".share-social"), "social row present after hover alone");
});

test("per-heading share: tap/click toggles a persistent .share-open; outside press + Escape close it", () => {
  const w = load(
    '<span class="share-tooltip" data-anchor="Sec">' +
    '<a class="headline-anchor" href="#Sec">s</a>' +
    '<span class="menu-wrapper"><span class="menu">' +
    '<span class="code-select" data-code="https://x.test/wiki/Page#Sec">p</span>' +
    '<template class="share-full"><span class="code-select" data-code="SEC">y</span></template>' +
    "</span></span></span>" +
    '<p id="elsewhere">body</p>');
  const tip = w.document.querySelector(".share-tooltip");
  const anchor = tip.querySelector(".headline-anchor");
  const click = () => {
    const ev = new w.MouseEvent("click", { bubbles: true, cancelable: true });
    anchor.dispatchEvent(ev);
    return ev;
  };
  // A tap/click opens a PERSISTENT state -- a mobile tap holds neither :hover nor :focus-within,
  // so without this the menu never stays open on a phone.
  const first = click();
  assert.ok(tip.classList.contains("share-open"), "tap opens the menu persistently");
  assert.ok(first.defaultPrevented, "the anchor's #id jump is suppressed so the tap opens the menu");
  // a second tap toggles it closed
  click();
  assert.ok(!tip.classList.contains("share-open"), "a second tap closes it");
  // reopen, then an OUTSIDE press dismisses it
  click();
  assert.ok(tip.classList.contains("share-open"), "reopened");
  w.document.getElementById("elsewhere").dispatchEvent(new w.Event("pointerdown", { bubbles: true }));
  assert.ok(!tip.classList.contains("share-open"), "an outside press closes the menu");
  // reopen, Escape closes
  click();
  assert.ok(tip.classList.contains("share-open"), "reopened again");
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.ok(!tip.classList.contains("share-open"), "Escape closes the menu");
});

test("hash navigation scrolls the target into view (content-visibility anchor fix)", () => {
  const w = load('<section class="cv-section"><h2 id="Sec">Sec</h2><p>x</p></section>'
    + '<section class="cv-section"><h2 id="Deep">Deep</h2><p>y</p></section>');
  const el = w.document.getElementById("Deep");
  let scrolled = 0;
  el.scrollIntoView = () => { scrolled++; };          // spy (jsdom's is a no-op)
  try { w.history.replaceState(null, "", "#Deep"); } catch (e) { /* jsdom */ }
  w.dispatchEvent(new w.Event("hashchange"));
  assert.equal(scrolled, 1, "a hash change scrolls the fragment target into view precisely");
  // no hash -> no scroll (guarded)
  const el2 = w.document.getElementById("Sec");
  let s2 = 0; el2.scrollIntoView = () => { s2++; };
  // w.location (NOT the bare test-realm `location`, which is undefined -> ReferenceError swallowed
  // by the catch, leaving the hash at '#Deep' so this asserted vacuously). Clear the fragment so
  // the hashchange genuinely exercises the no-fragment -> no-scroll path.
  try { w.history.replaceState(null, "", w.location.pathname); } catch (e) {}
  w.dispatchEvent(new w.Event("hashchange"));
  assert.equal(s2, 0, "no fragment -> no scroll");
});

test("print button invokes window.print without throwing", () => {
  let called = 0;
  const w = load('<button data-action="print">Print</button>');
  w.print = () => { called++; };
  w.document.querySelector('[data-action="print"]')
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(called, 1);
});

// ---- dark mode -----------------------------------------------------------------------------

test("dark-mode toggle flips data-theme and persists", () => {
  const w = load('<a href="#" data-darkmode>toggle</a>');
  const root = w.document.documentElement;
  w.document.querySelector("[data-darkmode]")
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(root.getAttribute("data-theme"), "dark");
  assert.equal(w.localStorage.getItem("theme"), "dark");
});

test("applyStoredTheme honours a stored light theme at load", () => {
  const w = load("<p>x</p>", { storage: { theme: "light" } });
  assert.equal(w.document.documentElement.getAttribute("data-theme"), "light");
});

// ---- collapsibles ---------------------------------------------------------------------------

test("native <details> collapsible needs no JS toggle (app.js leaves it alone)", () => {
  // Collapsibles are native <details class="mw-collapsible"> (render/collapsibles.py); the
  // <summary> is the toggle, so app.js must NOT inject the old .collapsible-toggle button.
  const w = load('<details class="mw-collapsible"><summary>H</summary><p>body</p></details>');
  const box = w.document.querySelector("details.mw-collapsible");
  assert.ok(box, "details collapsible present");
  assert.equal(box.querySelector(".collapsible-toggle"), null, "no injected toggle");
  assert.ok(box.querySelector("summary"), "native <summary> kept");
});

test("expand/collapse-all toggles every <details> collapsible", () => {
  const w = load(
    '<button class="expand-or-collapse-all-button">x</button>' +
    '<details class="mw-collapsible"></details>' +
    '<details class="mw-collapsible" open></details>');
  const all = w.document.querySelector(".expand-or-collapse-all-button");
  const items = () => [...w.document.querySelectorAll("details.mw-collapsible")];
  all.dispatchEvent(new w.Event("click", { bubbles: true }));  // one closed -> open all
  assert.equal(items().filter((d) => !d.open).length, 0, "all open after expand");
  all.dispatchEvent(new w.Event("click", { bubbles: true }));  // none closed -> close all
  assert.equal(items().filter((d) => d.open).length, 0, "all closed after collapse");
});

// ---- tabs ----------------------------------------------------------------------------------

test("tab controller builds a mininav switcher and activates on click", () => {
  const body = `
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section"><div class="tcc-title"><h3 id="one">One</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="two">Two</h3></div></div>
      </div>
    </div>`;
  const w = load(body);
  const ctrl = w.document.querySelector(".tab-content-controller");
  const pills = ctrl.querySelectorAll(".mininav .tcc-tab");
  assert.equal(pills.length, 2, "one pill per section");
  assert.equal(pills[0].textContent.trim(), "One", "labelled from title text");
  pills[1].dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const secs = ctrl.querySelectorAll(".tcc-content > .tcc-section");
  assert.ok(secs[1].classList.contains("active"), "second section active after click");
  assert.ok(!secs[0].classList.contains("active"), "first no longer active");
  // ARIA tabs pattern (injected by JS; no-JS stays plain stacked sections)
  const ul = ctrl.querySelector(".mininav > ul");
  assert.equal(ul.getAttribute("role"), "tablist", "mininav ul is a tablist");
  assert.equal(pills[0].getAttribute("role"), "tab", "pill is role=tab");
  assert.equal(secs[1].getAttribute("role"), "tabpanel", "section is role=tabpanel");
  assert.equal(pills[1].getAttribute("aria-controls"), secs[1].id, "tab controls its panel");
  assert.equal(secs[1].getAttribute("aria-labelledby"), pills[1].id, "panel labelled by its tab");
  assert.equal(pills[1].getAttribute("aria-selected"), "true", "active tab aria-selected");
  assert.equal(pills[0].getAttribute("aria-selected"), "false", "inactive tab not selected");
  assert.equal(pills[1].tabIndex, 0, "active tab in the tab sequence");
  assert.equal(pills[0].tabIndex, -1, "inactive tab out of the tab sequence (roving)");
});

test("tab controller: Arrow/Home/End move focus and activate (roving tabindex)", () => {
  const body = `
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section active"><div class="tcc-title"><h3 id="a">A</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="b">B</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="c">C</h3></div></div>
      </div>
    </div>`;
  const w = load(body);
  const ctrl = w.document.querySelector(".tab-content-controller");
  const ul = ctrl.querySelector(".mininav > ul");
  const pills = ctrl.querySelectorAll(".mininav .tcc-tab");
  const secs = ctrl.querySelectorAll(".tcc-content > .tcc-section");
  assert.equal(pills[0].getAttribute("aria-selected"), "true", "starts on the authored-active tab");
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.ok(secs[1].classList.contains("active"), "ArrowRight activates the next tab");
  assert.equal(pills[1].tabIndex, 0, "roving tabindex follows (next tab tabbable)");
  assert.equal(pills[0].tabIndex, -1, "previous tab leaves the tab sequence");
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "End", bubbles: true }));
  assert.ok(secs[2].classList.contains("active"), "End activates the last tab");
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.ok(secs[0].classList.contains("active"), "ArrowRight wraps to the first");
});

test("tab click anchors location.hash to the chosen section id", () => {
  const body = `
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section"><div class="tcc-title"><h3 id="one">One</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="two">Two</h3></div></div>
      </div>
    </div>`;
  const w = load(body);
  const pills = w.document.querySelectorAll(".mininav .tcc-tab");
  pills[1].dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.location.hash, "#two", "URL hash follows the chosen tab");
  pills[0].dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.location.hash, "#one", "hash updates on each tab switch");
});

test("tab click percent-encodes a special section id so reload decode round-trips", () => {
  const body = `
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section"><div class="tcc-title"><h3 id="a">A</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="100%_Done">B</h3></div></div>
      </div>
    </div>`;
  const w = load(body);
  const pills = w.document.querySelectorAll(".mininav .tcc-tab");
  // the pill's href (the shared/open-in-new-tab URL) is encoded too, not just the click handler
  assert.equal(pills[1].getAttribute("href"), "#100%25_Done", "pill href is percent-encoded");
  pills[1].dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.location.hash, "#100%25_Done", "a raw % in the id is percent-encoded");
  // decodeURIComponent of the fragment must NOT throw (syncTabsFromHash does this on reload)
  assert.equal(decodeURIComponent(w.location.hash.slice(1)), "100%_Done");
});

test("hash tab-sync: target element reachable, no throw", () => {
  const body = `
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section" id="s1"><div class="tcc-title"><h3 id="t1">a</h3></div></div>
        <div class="tcc-section" id="s2"><div class="tcc-title"><h3 id="target">b</h3></div></div>
      </div>
    </div>`;
  const w = load(body, { hash: "#target" });
  assert.ok(w.document.getElementById("target"), "target present");
  w.dispatchEvent(new w.Event("hashchange"));
});

test("FUZZ: adversarial location.hash never throws", () => {
  const hostile = [
    '#a"]', "#a'])", "#*", "#..//", "#%E0%A4%A", "#" + "x".repeat(5000),
    "#<script>", "#a b c", "#]]{{", "#&amp;", "#%", "#%zz", "#:::", "#../../x",
  ];
  for (const h of hostile) {
    assert.doesNotThrow(() => {
      const w = load(
        '<div class="tab-content-controller"><div class="mininav"></div>' +
        '<div class="tcc-content"><div class="tcc-section" id="s">' +
        '<div class="tcc-title"><h3 id="h">x</h3></div></div></div></div>',
        { hash: h });
      w.location.hash = h;
      w.dispatchEvent(new w.Event("hashchange"));
    }, `hash ${JSON.stringify(h)} must not throw`);
  }
});

// ---- nav / back-to-top / search -------------------------------------------------------------

test("nav toggle: Escape handler closes an open menu", () => {
  const w = load(`
    <header class="site-header"><div class="site-header-inner">
      <input type="checkbox" id="nav-toggle" class="nav-toggle">
      <nav class="site-nav"><a href="#x">link</a></nav>
    </div></header><main>body</main>`);
  const cb = w.document.getElementById("nav-toggle");
  cb.checked = true;
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.equal(cb.checked, false, "Escape closed the menu");
});

test("back-to-top: static anchor is wired hidden and reveals past the scroll threshold", () => {
  // Back-to-top is STATIC HTML now (page.py: <a class="back-to-top" href="#top">) so it works
  // with no JS; initBackToTop ENHANCES the existing element (sets hidden + wires scroll), it
  // no longer appends one -- so the test must provide the static anchor.
  const w = load('<main>x</main><a class="back-to-top" href="#top">Top</a>');
  const btn = w.document.querySelector(".back-to-top");
  assert.ok(btn && btn.hidden, "present and hidden at top");
  Object.defineProperty(w, "scrollY", { value: 800, configurable: true });
  w.dispatchEvent(new w.Event("scroll"));
  assert.equal(btn.hidden, false, "revealed after scrolling down");
});

test("search filters the prebuilt index and renders result links", async () => {
  // The index is fetched (carrier + stubbed fetch) on first interaction, so drive the input
  // then await a tick to let ensureIndex().then(render) resolve.
  const w = load('<input id="search-input">',
    { searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }, { t: "Tor", u: "wiki/Tor/" }] });
  const input = w.document.getElementById("search-input");
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  const links = w.document.querySelectorAll(".search-results li a");
  assert.equal(links.length, 1, "one match for 'fire'");
  assert.equal(links[0].textContent, "Firewall");
});

test("search: unchecking the magnifier toggle hides AND clears the results dropdown", async () => {
  const w = load(
    '<span class="site-search"><input type="checkbox" id="search-toggle"><input id="search-input"></span>',
    { searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }] });
  const toggle = w.document.getElementById("search-toggle");
  const input = w.document.getElementById("search-input");
  const results = w.document.querySelector(".search-results");
  // open the box and run a query so the dropdown is visible + populated
  toggle.checked = true;
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  assert.ok(!results.hidden, "results dropdown is open after a query");
  assert.ok(results.querySelector("li a"), "results are populated");
  // a USER unchecking the magnifier (collapsing the box) fires 'change' -> must FULLY close:
  // hide + clear, else the dropdown (now showing full-text body rows) lingers over the page
  toggle.checked = false;
  toggle.dispatchEvent(new w.Event("change"));
  assert.ok(results.hidden, "results dropdown is hidden after unchecking the toggle");
  assert.equal(results.querySelector("li a"), null, "results are cleared on close");
});

test("search hides namespaced (n:1) pages unless the query is namespace-qualified", async () => {
  async function run(query) {
    const w = load('<input id="search-input">',
      { searchIndex: [{ t: "Box", u: "wiki/Box/" },
                      { t: "Template:Box", u: "wiki/Template:Box/", n: 1 }] });
    const input = w.document.getElementById("search-input");
    input.value = query;
    input.dispatchEvent(new w.Event("input"));
    await tick();
    return Array.from(w.document.querySelectorAll(".search-results li a")).map((a) => a.textContent);
  }
  // plain query: only the main-namespace page, Template: hidden
  assert.deepEqual(await run("box"), ["Box"], "plain query must not surface the Template: page");
  // namespace-qualified query: the Template: page is surfaced
  assert.ok((await run("template:box")).includes("Template:Box"),
    "a namespace-qualified query must surface the Template: page");
});

test("search namespace filter matches the entry's namespace, not just any colon", async () => {
  async function run(query) {
    const w = load('<input id="search-input">',
      { searchIndex: [{ t: "Template:Foo:Bar", u: "wiki/Template:Foo:Bar/", n: 1 }] });
    const input = w.document.getElementById("search-input");
    input.value = query;
    input.dispatchEvent(new w.Event("input"));
    await tick();
    return Array.from(w.document.querySelectorAll(".search-results li a")).map((a) => a.textContent);
  }
  // a colon that is NOT the page's namespace must not surface it (query ns "foo" != "template")
  assert.deepEqual(await run("foo:bar"), [],
    "a non-namespace colon query must not surface a namespaced page");
  // the page's own namespace does surface it
  assert.ok((await run("template:foo")).includes("Template:Foo:Bar"),
    "the page's own namespace query surfaces it");
});

test("search result href uses the root prefix from app.min.js (deployed), not doubling /wiki/", async () => {
  // Deployed pages load app.min.js (minified). rootPrefix must match it, else a /wiki/ page
  // gets root="" and the search link "wiki/<t>" resolves against /wiki/ -> /wiki/wiki/<t>.
  const w = load('<input id="search-input">',
    { appSrc: "../app.min.js", url: "https://x.test/wiki/Bitcoin",
      searchIndex: [{ t: "Firewall", u: "wiki/Firewall" }] });
  const input = w.document.getElementById("search-input");
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  const a = w.document.querySelector(".search-results li a");
  assert.ok(a, "a result link is rendered");
  // depth-1 page -> root "../"; href must be "../wiki/Firewall", NOT "wiki/Firewall" (which
  // the browser would resolve to /wiki/wiki/Firewall).
  assert.equal(a.getAttribute("href"), "../wiki/Firewall",
    "search href must carry the ../ root prefix (app.min.js matched)");
});

test("search root prefix survives the post-build ?h= cache-buster (real deployed page)", async () => {
  // The fingerprint pass (assets.py) appends ?h=<hash> to every asset src, so the deployed
  // src is "../app.min.js?h=<hex>", NOT a bare "../app.min.js". A $-anchored rootPrefix regex
  // fails to match that -> root="" -> /wiki/wiki/<target>. Mirror a real deployed head: the
  // app.min.js src carries the query, alongside the instant.page module script -- the dangerous
  // look-alike that must NOT be mistaken for app.js. (The search/preview indexes are now inert
  // <link> carriers, not <script>, so rootPrefix's script scan never even sees them.)
  const w = load('<input id="search-input">', {
    appSrc: "../app.min.js?h=187f5d81",
    url: "https://x.test/wiki/Bitcoin",
    headExtra: '<script type="module" src="../libs/instant.page/instantpage.min.js"></script>',
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall" }],
  });
  const input = w.document.getElementById("search-input");
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  const a = w.document.querySelector(".search-results li a");
  assert.ok(a, "a result link is rendered");
  assert.equal(a.getAttribute("href"), "../wiki/Firewall",
    "fingerprinted app.min.js?h= must still yield the ../ root prefix (no /wiki/ doubling)");
  // And the resolved URL is single-/wiki/, exactly what the browser would navigate to.
  assert.equal(new w.URL(a.getAttribute("href"), w.location.href).pathname,
    "/wiki/Firewall", "resolved search href must not double /wiki/");
});

test("search closes on outside click and Escape, clearing the live results", async () => {
  const w = load('<div class="site-search"><input type="checkbox" id="search-toggle">' +
    '<input id="search-input"></div><p id="elsewhere">x</p>',
    { searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }, { t: "Tor", u: "wiki/Tor/" }] });
  const toggle = w.document.getElementById("search-toggle");
  const input = w.document.getElementById("search-input");
  const results = w.document.querySelector(".search-results");
  // open + type -> results shown (await the index fetch)
  toggle.checked = true;
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  assert.equal(results.hidden, false, "results shown after typing");
  // a click INSIDE the widget keeps it open
  input.dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(toggle.checked, true, "inside click stays open");
  // a click OUTSIDE unchecks the toggle AND hides + clears the results
  w.document.getElementById("elsewhere").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(toggle.checked, false, "outside click unchecks the toggle");
  assert.ok(results.hidden && results.children.length === 0, "outside click hides+clears results");
  // reopen, then Escape closes
  toggle.checked = true;
  input.value = "tor";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape" }));
  assert.equal(toggle.checked, false, "Escape closes the box");
});

// ---- banners (consent / stage / sitenotice) -------------------------------------------------

test("consent banner: checkbox change persists / un-persists the dismissal", () => {
  // No-JS dismiss is the CSS checkbox-hack (sr-only #consent-dismiss-cb + OK label); the hide
  // is pure CSS (:checked + .consent-banner). JS only persists the toggle across pages.
  const w = load('<div class="bottom-stack">' +
    '<input type="checkbox" id="consent-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="consent-banner"><label for="consent-dismiss-cb" data-consent-dismiss>OK</label>' +
    '</div></div>');
  const cb = w.document.getElementById("consent-dismiss-cb");
  cb.checked = true;
  cb.dispatchEvent(new w.Event("change", { bubbles: true }));
  assert.equal(w.localStorage.getItem("legal-agreement-banner-dismissed"), "1", "checking persists");
  cb.checked = false;
  cb.dispatchEvent(new w.Event("change", { bubbles: true }));
  assert.equal(w.localStorage.getItem("legal-agreement-banner-dismissed"), null, "unchecking un-persists");
});

test("consent banner: a persisted dismissal pre-checks the box on load", () => {
  const w = load('<div class="bottom-stack">' +
    '<input type="checkbox" id="consent-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="consent-banner"><label for="consent-dismiss-cb" data-consent-dismiss>OK</label>' +
    '</div></div>', { storage: { "legal-agreement-banner-dismissed": "1" } });
  assert.ok(w.document.getElementById("consent-dismiss-cb").checked,
    "persisted dismissal pre-checks the box (CSS :checked then hides the banner)");
});

test("stage banner: checkbox change persists the dismissal", () => {
  // No-JS dismiss is the CSS checkbox-hack (hide is pure CSS); JS persists across pages.
  const w = load('<div class="bottom-stack">' +
    '<input type="checkbox" id="stage-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="stage-banner" role="alert"><label for="stage-dismiss-cb" data-stage-dismiss>OK</label>' +
    '</div></div>');
  const cb = w.document.getElementById("stage-dismiss-cb");
  cb.checked = true;
  cb.dispatchEvent(new w.Event("change", { bubbles: true }));
  assert.equal(w.localStorage.getItem("stage-notice-dismissed"), "1", "checking persists");
  cb.checked = false;
  cb.dispatchEvent(new w.Event("change", { bubbles: true }));
  assert.equal(w.localStorage.getItem("stage-notice-dismissed"), null, "unchecking un-persists");
});

test("sitenotice: dismiss stores the banner id; a matching stored id pre-hides", () => {
  const w = load('<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="38">promo</div>' +
    '<button data-sitenotice-dismiss>x</button></div>');
  w.document.querySelector("[data-sitenotice-dismiss]").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(w.localStorage.getItem("sitenotice-dismissed"), "38");
  const w2 = load('<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="38">promo</div>' +
    '<button data-sitenotice-dismiss>x</button></div>', { storage: { "sitenotice-dismissed": "38" } });
  assert.ok(w2.document.getElementById("siteNotice").hidden, "same id pre-hidden");
});

test("sitenotice force-show ignores a stored dismissal", () => {
  const w = load('<div id="siteNotice"><div class="sitenotice-banner force-show" data-banner-id="eoy">x</div></div>',
    { storage: { "sitenotice-dismissed": "eoy" } });
  assert.ok(!w.document.getElementById("siteNotice").hidden, "force-show stays visible");
});

// ---- fly-in toast --------------------------------------------------------------------------

test("fly-in toast: test-settings forces it to show, close button hides + persists", async () => {
  const w = load(
    '<div id="fly-in-notification-panel" hidden>' +
    '<button class="close-panel">x</button></div>' +
    '<div id="fly-in-notification-test-settings" data-waitinseconds="0" ' +
    'data-dismissfordays="3" data-now="1700000500000"></div>');
  await tick();
  const panel = w.document.getElementById("fly-in-notification-panel");
  assert.equal(panel.hidden, false, "toast shown after the (0s) wait");
  panel.querySelector(".close-panel").dispatchEvent(new w.Event("click", { bubbles: true }));
  // Privacy: the dismissal timestamp is rounded DOWN to the day (the read only compares at
  // day granularity), so the stored value is day-aligned and within the dismissal day.
  const stored = parseInt(w.localStorage.getItem("flyin-last-dismissed"), 10);
  const DAY = 86400000, now = 1700000500000;
  assert.equal(stored % DAY, 0, "dismissal timestamp rounded to the day (privacy)");
  assert.ok(stored <= now && now - stored < DAY, "rounded value is within the dismissal day");
});

// ---- modals (generic / download / table-expand) --------------------------------------------

test("generic modal: a trigger opens it, Escape closes it", () => {
  const w = load('<button data-modal-open="m1">open</button>' +
    '<div id="m1" class="mini-modal" hidden><div class="underlay"></div>' +
    '<button class="mm-close">x</button></div>');
  w.document.querySelector("[data-modal-open]")
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const m = w.document.getElementById("m1");
  assert.ok(m.classList.contains("active"), "opened");
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.ok(!m.classList.contains("active"), "Escape closed it");
});

test("download modal: dlbtn click is intercepted and opens a modal", () => {
  const w = load('<a class="download-button-v2 dlbtn-modal" href="https://dl.test/f.iso">Get</a>');
  w.document.querySelector("a.dlbtn-modal")
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.ok(w.document.getElementById("download-button-modal"), "download modal created");
});

test("table expand: caption gets an Expand button that opens a cloned-table modal", () => {
  const w = load('<div class="wiki-content"><table><caption>Compare</caption>' +
    '<tr id="row1"><td>a</td></tr></table></div>');
  const btn = w.document.querySelector(".expand-table-button");
  assert.ok(btn, "expand button inserted into caption");
  btn.dispatchEvent(new w.Event("click", { bubbles: true }));
  const modal = w.document.querySelector(".table-expand-modal");
  assert.ok(modal && modal.classList.contains("active"), "modal opened");
  assert.ok(!modal.querySelector("#row1"), "ids stripped from the clone");
});

test("comparison-more: JS reveals the control, collapses extras, button toggles them", () => {
  const w = load('<div class="wiki-content"><table class="comparison-table"><tbody>' +
    '<tr><td>Primary</td></tr>' +
    '<tr class="cmp-more-ctrl" hidden><td colspan="3">' +
    '<button type="button" class="cmp-more-btn" aria-expanded="false">Compare more features</button></td></tr>' +
    '<tr class="cmp-extra"><td>Extra A</td></tr>' +
    '<tr class="cmp-extra"><td>Extra B</td></tr>' +
    '<tr><td>Pricing</td></tr></tbody></table></div>');
  const table = w.document.querySelector(".comparison-table");
  const ctrl = w.document.querySelector(".cmp-more-ctrl");
  const btn = w.document.querySelector(".cmp-more-btn");
  // on load: control revealed (was hidden for no-JS), extras collapsed
  assert.equal(ctrl.hidden, false, "control row revealed by JS");
  assert.ok(table.classList.contains("cmp-collapsed"), "extras collapsed on load");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
  // click -> expand
  btn.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  assert.ok(!table.classList.contains("cmp-collapsed"), "click expands the extra rows");
  assert.equal(btn.getAttribute("aria-expanded"), "true");
  // click -> collapse again
  btn.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  assert.ok(table.classList.contains("cmp-collapsed"), "click re-collapses");
  assert.equal(btn.getAttribute("aria-expanded"), "false");
});

// ---- hovercards / storage viewer / wide tables ----------------------------------------------

test("hovercards: hovering a reference link builds a card from the footnote", async () => {
  const w = load('<div class="wiki-content"><sup class="reference"><a href="#fn1">[1]</a></sup>' +
    '<li id="fn1">A footnote. <span class="mw-cite-backlink">^</span></li></div>');
  const a = w.document.querySelector("sup.reference a");
  a.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 260));  // showTimer is 200ms
  const card = w.document.querySelector(".hovercard .hovercard-ref");
  assert.ok(card, "ref hovercard built");
  assert.ok(/A footnote/.test(card.textContent), "footnote text carried over");
  assert.ok(!/\^/.test(card.textContent), "backlink caret dropped");
});

test("hovercards: a reference card carries a prev/next navigator that browses all notes in place", async () => {
  const w = load('<div class="wiki-content">' +
    '<sup class="reference"><a href="#fn1">[1]</a></sup>' +
    '<sup class="reference"><a href="#fn2">[2]</a></sup>' +
    '<sup class="reference"><a href="#fn3">[3]</a></sup>' +
    '<li id="fn1">First note.</li><li id="fn2">Second note.</li><li id="fn3">Third note.</li></div>');
  const a = w.document.querySelectorAll("sup.reference a")[0];
  a.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 260));
  let card = w.document.querySelector(".hovercard");
  assert.ok(/First note/.test(card.textContent), "opens on the hovered note");
  assert.ok(card.querySelector(".hovercard-nav"), "nav present when the page has >1 note");
  assert.ok(/1 \/ 3/.test(card.querySelector(".hovercard-pos").textContent), "position reads 1 / 3");
  // next -> note 2, content flips in place (same card element)
  card.querySelectorAll(".hovercard-navbtn")[1].dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  card = w.document.querySelector(".hovercard");
  assert.ok(/Second note/.test(card.textContent) && /2 \/ 3/.test(card.querySelector(".hovercard-pos").textContent), "next flips to note 2 / 3");
  // prev from note 1 wraps to the last: 2 -> 1 -> 3
  card.querySelectorAll(".hovercard-navbtn")[0].dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  w.document.querySelector(".hovercard").querySelectorAll(".hovercard-navbtn")[0].dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  assert.ok(/Third note/.test(w.document.querySelector(".hovercard").textContent), "prev wraps to the last note");
});

test("hovercards: a citation low in the viewport flips the card ABOVE and caps to the room", async () => {
  const w = load('<div class="wiki-content"><sup class="reference"><a href="#fn1">[1]</a></sup>' +
    '<li id="fn1">A footnote.</li></div>');
  const a = w.document.querySelector("sup.reference a");
  // Put the citation near the viewport bottom: above(=top-14)=686 > below(=innerHeight-bottom-14)=34
  // and above>160, so place() takes the useAbove=true path (flip above, cap maxHeight to the room).
  a.getBoundingClientRect = () => ({ top: 700, bottom: 720, left: 10, right: 30, width: 20, height: 20 });
  a.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 260));
  const card = w.document.querySelector(".hovercard");
  assert.ok(card, "card built");
  // maxHeight capped to the (large) room ABOVE, not the tiny room below -> useAbove branch taken.
  assert.ok(parseFloat(card.style.maxHeight) > 120, "maxHeight capped to the room above, not below");
  assert.ok(parseFloat(card.style.top) < 700, "card placed above the low citation");
});

test("hovercards: reference card has a 'Footnote N' headline, nav on top, arrow + Escape keys", async () => {
  const w = load('<div class="wiki-content">' +
    '<sup class="reference"><a href="#fn1">[1]</a></sup>' +
    '<sup class="reference"><a href="#fn2">[2]</a></sup>' +
    '<li id="fn1">First note.</li><li id="fn2">Second note.</li></div>');
  w.document.querySelectorAll("sup.reference a")[0]
    .dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 260));
  const card = w.document.querySelector(".hovercard");
  const title = card.querySelector(".hovercard-title");
  assert.ok(title && /^Footnote 1$/.test(title.textContent.trim()), "headline reads 'Footnote 1'");
  // nav bar sits ABOVE the note text (DOM order: nav precedes the ref body)
  const kids = [].slice.call(card.children);
  assert.ok(kids.indexOf(card.querySelector(".hovercard-nav")) < kids.indexOf(card.querySelector(".hovercard-ref")),
    "nav bar is on top (before the note text)");
  // ArrowRight steps to note 2 in place; headline tracks the shown note
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.ok(/Second note/.test(w.document.querySelector(".hovercard").textContent), "ArrowRight flips to note 2");
  assert.ok(/^Footnote 2$/.test(w.document.querySelector(".hovercard .hovercard-title").textContent.trim()),
    "headline updates to 'Footnote 2'");
  // ArrowLeft steps back to note 1
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
  assert.ok(/First note/.test(w.document.querySelector(".hovercard").textContent), "ArrowLeft steps back to note 1");
  // Escape dismisses the card
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.ok(w.document.querySelector(".hovercard").hidden, "Escape hides the card");
});

test("hovercards: hovering an internal link builds a page card from the fetched preview index", async () => {
  // Previews are lazy: fetched (carrier + stubbed fetch) on first in-content hover, then the
  // card renders once resolved + the 200ms dwell elapses. Depth-1 page (app.min.js at ../),
  // so rootPrefix="../" -> site root; the relative anchor "Firewall/" resolves to the index key
  // "wiki/Firewall/".
  const w = load('<div class="wiki-content"><p><a href="Firewall/">Firewall</a></p></div>',
    { appSrc: "../app.min.js",
      previews: { "wiki/Firewall/": { t: "Firewall", d: "Blocks unwanted traffic." } } });
  const a = w.document.querySelector(".wiki-content a");
  a.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await tick();                                   // let ensurePreviews() resolve
  await new Promise((r) => setTimeout(r, 260));   // showTimer is 200ms
  const card = w.document.querySelector(".hovercard .hovercard-page");
  assert.ok(card, "page-preview hovercard built from the fetched index");
  assert.ok(/Blocks unwanted traffic/.test(card.textContent), "summary carried over");
});

test("storage viewer: renders a row per registry key; shows VALUES; Delete-all clears", () => {
  // Use a value that is NOT a substring of any registry label, so the assertion proves the
  // value cell renders (a label like "Color theme (dark / light)" would match a naive /dark/).
  const w = load('<div data-storage-viewer></div>',
    { storage: { "flyin-last-dismissed": "1700000000", theme: "dark" } });
  const mount = w.document.querySelector("[data-storage-viewer]");
  const rows = mount.querySelectorAll("tbody tr");
  assert.ok(rows.length >= 5, "at least one row per known key");
  assert.ok(/1700000000/.test(mount.textContent), "shows the stored value (not just the label)");
  assert.ok(mount.querySelector(".storage-del"), "a set key gets a per-item Delete button");
  mount.querySelector(".storage-clear").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(w.localStorage.length, 0, "Delete-all emptied storage");
});

test("gallery lightbox: a.glb-link click opens overlay (nav prevented); next wraps; link= opts out", () => {
  const w = load(
    '<div class="gallery">' +
    '<span class="gallerybox"><a class="glb-link" href="a.webp"><span class="thumb">' +
    '<img src="a.webp" alt="A"></span></a><span class="gallerytext">Alpha</span></span>' +
    '<span class="gallerybox"><a class="glb-link" href="b.webp"><span class="thumb">' +
    '<img src="b.webp" alt="B"></span></a><span class="gallerytext">Beta</span></span>' +
    '<span class="gallerybox"><a href="/wiki/Donate"><span class="thumb">' +
    '<img src="c.webp" alt="C"></span></a><span class="gallerytext">Gamma</span></span>' +
    '</div>');
  const links = w.document.querySelectorAll(".gallery .gallerybox > a");
  assert.ok(links[0].classList.contains("glb-link"), "eligible thumb wrapped in a.glb-link");
  assert.ok(!links[2].classList.contains("glb-link"), "link= thumb opted out of the lightbox");
  // clicking an eligible anchor opens the modal instead of navigating to the image
  const ev = new w.MouseEvent("click", { bubbles: true, cancelable: true });
  links[1].dispatchEvent(ev);
  assert.ok(ev.defaultPrevented, "navigation prevented on a lightbox anchor");
  const lb = w.document.querySelector(".gallery-lightbox");
  assert.ok(lb && lb.classList.contains("active"), "lightbox opened");
  assert.equal(lb.querySelector(".glb-image").getAttribute("src"), "b.webp", "opened at clicked index");
  assert.equal(lb.querySelector(".glb-caption").textContent, "Beta");
  lb.querySelector(".glb-next").dispatchEvent(new w.Event("click", { bubbles: true }));
  // only 2 eligible items (Gamma excluded) -> next from Beta(idx1) wraps to Alpha(idx0)
  assert.equal(lb.querySelector(".glb-image").getAttribute("src"), "a.webp", "next wraps around");
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.equal(lb.querySelector(".glb-image").getAttribute("src"), "b.webp", "ArrowRight advances");
});

test("gallery lightbox: single-image gallery opens on click, no prev/next", () => {
  const w = load('<div class="gallery"><span class="gallerybox"><a class="glb-link" href="solo.webp">' +
    '<span class="thumb"><img src="solo.webp" alt="S"></span></a>' +
    '<span class="gallerytext">Solo</span></span></div>');
  const a = w.document.querySelector(".gallery .gallerybox > a.glb-link");
  const ev = new w.MouseEvent("click", { bubbles: true, cancelable: true });
  a.dispatchEvent(ev);
  assert.ok(ev.defaultPrevented, "navigation prevented");
  assert.ok(w.document.querySelector(".gallery-lightbox.active"), "click opens the lightbox");
  assert.ok(!w.document.querySelector(".glb-nav"), "no nav buttons for a lone image");
});

test("expand-table clone neutralizes a.glb-link so a cloned gallery thumb is inert", () => {
  const w = load('<div class="wiki-content"><table><caption>Compare</caption>' +
    '<tr><td><div class="gallery"><span class="gallerybox"><a class="glb-link" href="a.webp">' +
    '<span class="thumb"><img src="a.webp" alt="A"></span></a><span class="gallerytext">A</span></span>' +
    '</div></td></tr></table></div>');
  // the in-page thumb is lightbox-eligible (wrapped in a.glb-link)...
  assert.ok(w.document.querySelector(".gallery .gallerybox > a.glb-link"), "in-page thumb is a.glb-link");
  w.document.querySelector(".expand-table-button").dispatchEvent(new w.Event("click", { bubbles: true }));
  const clonedA = w.document.querySelector(".table-expand-modal .gallery .gallerybox > a");
  assert.ok(clonedA, "cloned gallery present in modal");
  assert.ok(!clonedA.classList.contains("glb-link"), "clone glb-link class stripped");
  assert.equal(clonedA.getAttribute("href"), null, "clone href stripped -> inert, no navigation");
});

test("wide-table scroll init is total on a table (no throw)", () => {
  assert.doesNotThrow(() =>
    load('<div class="wiki-content"><table><tr><td>x</td></tr></table></div>'));
});

// jsdom computes no layout, so override the geometry getters. `railLog` records, at each
// scrollWidth READ, whether a top rail already exists in the DOM -- a read that sees one
// proves a style WRITE ran between two reads (the forced-reflow thrash we fixed).
function stubTableGeom(doc, el, scrollWidth, clientWidth, railLog) {
  Object.defineProperty(el, "scrollWidth", { configurable: true, get() {
    if (railLog) railLog.push(!!doc.querySelector(".table-scroll-top"));
    return scrollWidth;
  } });
  Object.defineProperty(el, "clientWidth", { configurable: true, get() { return clientWidth; } });
}

test("wide tables: one ResizeObserver batches all reads before any style write (no reflow thrash)", () => {
  const w = load('<div class="wiki-content">' +
    '<table id="wide"><tbody><tr><td>x</td></tr></tbody></table>' +
    '<table id="fits"><tbody><tr><td>y</td></tr></tbody></table></div>');
  // Batched design: a SINGLE shared observer over every table (the old code made one per
  // table, each interleaving read->write->read -> the ~83ms forced synchronous layout).
  assert.equal(w.__resizeObservers.length, 1, "one shared ResizeObserver for all tables");
  const ro = w.__resizeObservers[0];
  assert.equal(ro.targets.length, 2, "it observes every table");

  const railLog = [];
  const wide = w.document.getElementById("wide");
  const fits = w.document.getElementById("fits");
  stubTableGeom(w.document, wide, 400, 200, railLog);  // overflows -> needs a rail
  stubTableGeom(w.document, fits, 150, 200, railLog);  // fits -> no rail

  ro.cb();  // one batched callback == the frame's resize delivery for all tables

  assert.ok(railLog.length >= 2, "every table's geometry was read");
  assert.ok(railLog.every((sawRail) => sawRail === false),
    "no scrollWidth read saw an already-built rail -> all reads precede all writes");

  // Behaviour preserved: the overwide table gets a top rail whose spacer == its scrollWidth;
  // the fitting table gets none.
  const rail = wide.previousElementSibling;
  assert.ok(rail && rail.classList.contains("table-scroll-top"), "overwide table got a top rail");
  assert.equal(rail.firstChild.style.width, "400px", "spacer width == table scrollWidth");
  assert.equal(rail.style.display, "", "rail shown while overwide");
  assert.equal(wide.style.marginTop, "0px", "overwide table pinned under the rail");
  const fitsPrev = fits.previousElementSibling;
  assert.ok(!(fitsPrev && fitsPrev.classList && fitsPrev.classList.contains("table-scroll-top")),
    "fitting table gets no rail");
});

// ---- totality ------------------------------------------------------------------------------

test("init is total on a minimal document (no throw)", () => {
  assert.doesNotThrow(() => load("<p>nothing to enhance</p>"));
});

// ---- header nav keyboard (#69): idiomatic menubar arrow-key navigation ----------------------

const NAV = '<header><nav class="site-nav"><ul>' +
  '<li class="nav-group"><a class="nav-top" href="/a">A</a><ul class="nav-submenu">' +
  '<li><a href="/a1">A1</a></li><li><a href="/a2">A2</a></li></ul></li>' +
  '<li class="nav-group"><a class="nav-top" href="/b">B</a><ul class="nav-submenu">' +
  '<li><a href="/b1">B1</a></li></ul></li></ul></nav></header>';

function navSetup() {
  const w = load(NAV);
  const nav = w.document.querySelector(".site-nav > ul");
  const tops = [...nav.querySelectorAll(":scope > li > .nav-top")];
  const key = (el, k) => el.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true }));
  return { w, nav, tops, key };
}

test("nav keyboard: menubar roles + roving tabindex applied", () => {
  const { nav, tops } = navSetup();
  assert.equal(nav.getAttribute("role"), "menubar");
  assert.equal(tops[0].getAttribute("role"), "menuitem");
  assert.equal(tops[0].tabIndex, 0, "first top item is the single tab stop");
  assert.equal(tops[1].tabIndex, -1, "other top items out of the tab sequence");
  assert.equal(tops[0].getAttribute("aria-haspopup"), "true");
  assert.equal(tops[0].getAttribute("aria-expanded"), "false");
});

test("nav keyboard: ArrowRight/Left move between top items (wrap)", () => {
  const { tops, key } = navSetup();
  tops[0].focus();
  key(tops[0], "ArrowRight");
  assert.equal(tops[1].tabIndex, 0, "ArrowRight moves roving focus to the next top item");
  assert.equal(tops[0].tabIndex, -1);
  key(tops[1], "ArrowRight");
  assert.equal(tops[0].tabIndex, 0, "ArrowRight wraps to the first");
  key(tops[0], "ArrowLeft");
  assert.equal(tops[1].tabIndex, 0, "ArrowLeft wraps to the last");
});

test("nav keyboard: ArrowDown opens submenu + focuses first item; Escape returns", () => {
  const { w, tops, key } = navSetup();
  tops[0].focus();
  key(tops[0], "ArrowDown");
  const g0 = tops[0].closest("li");
  assert.ok(g0.classList.contains("kb-open"), "ArrowDown opens the submenu");
  assert.equal(tops[0].getAttribute("aria-expanded"), "true");
  assert.equal(w.document.activeElement.textContent, "A1", "first submenu item focused");
  key(w.document.activeElement, "ArrowDown");
  assert.equal(w.document.activeElement.textContent, "A2", "ArrowDown moves within the submenu");
  key(w.document.activeElement, "Escape");
  assert.ok(!g0.classList.contains("kb-open"), "Escape closes the submenu");
  assert.equal(tops[0].getAttribute("aria-expanded"), "false");
  assert.equal(w.document.activeElement, tops[0], "Escape returns focus to the top item");
});

test("nav keyboard: inert with fewer than 2 top items", () => {
  const w = load('<nav class="site-nav"><ul><li><a href="/only">Only</a></li></ul></nav>');
  assert.notEqual(w.document.querySelector(".site-nav > ul").getAttribute("role"), "menubar");
});

// ---- load lifecycle (ready / whenIdle) ------------------------------------------------------

test("ready(): inits immediately when the document is already loaded (not 'loading')", () => {
  // readyState !== "loading" at IIFE time -> ready() calls the init synchronously, no DOMContentLoaded wait.
  const w = load('<span class="code-select" data-code="x">x</span>', {
    preEval: (win) => Object.defineProperty(win.document, "readyState", { value: "complete", configurable: true }),
  });
  assert.ok(w.document.querySelector(".code-select").classList.contains("js-fully-loaded"),
    "enrichment ran at load time without a DOMContentLoaded dispatch");
});

test("whenIdle(): defers through requestIdleCallback when the engine provides it", () => {
  let idleCalls = 0;
  const w = load('<span class="code-select" data-code="x">x</span>', {
    preEval: (win) => { win.requestIdleCallback = (fn) => { idleCalls++; fn(); }; },
  });
  assert.ok(idleCalls > 0, "the idle-deferred setup went through requestIdleCallback");
  assert.ok(w.document.querySelector(".code-select").classList.contains("js-fully-loaded"),
    "the deferred code-select enrichment still ran");
});

// ---- theme edge paths -----------------------------------------------------------------------

test("dark-mode toggle returns to light on a second click", () => {
  const w = load('<a href="#" data-darkmode>t</a>');
  const root = w.document.documentElement;
  const link = w.document.querySelector("[data-darkmode]");
  const click = () => link.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  click();
  assert.equal(root.getAttribute("data-theme"), "dark");
  click();
  assert.equal(root.getAttribute("data-theme"), "light", "second click flips dark -> light");
  assert.equal(w.localStorage.getItem("theme"), "light");
});

test("applyStoredTheme honours prefers-color-scheme:dark when nothing is stored", () => {
  const w = load("<p>x</p>", {
    preEval: (win) => { win.matchMedia = () => ({ matches: true, addEventListener() {}, addListener() {} }); },
  });
  assert.equal(w.document.documentElement.getAttribute("data-theme"), "dark",
    "the system dark preference applies the dark theme with no stored choice");
});

// ---- copy widgets: clipboard + selection fallbacks ------------------------------------------

test("code-select copy uses the async clipboard API when present (marks copied, swaps glyph)", async () => {
  const w = load('<span class="code-select" data-code="hello">x</span>', {
    preEval: (win) => { win.navigator.clipboard = { writeText: () => Promise.resolve() }; },
  });
  const cs = w.document.querySelector(".code-select");
  const btn = cs.querySelector(".cbutton");
  btn.dispatchEvent(new w.Event("click", { bubbles: true }));
  await tick();
  assert.ok(cs.classList.contains("copied"), "a successful clipboard write marks copied");
  assert.ok(btn.classList.contains("fa-check"), "the glyph swaps to a check on copy");
});

test("code-select copy falls back to selecting the text when the clipboard write rejects", async () => {
  const w = load('<span class="code-select" data-code="hello">x</span>', {
    preEval: (win) => { win.navigator.clipboard = { writeText: () => Promise.reject(new Error("denied")) }; },
  });
  const cs = w.document.querySelector(".code-select");
  cs.querySelector(".cbutton").dispatchEvent(new w.Event("click", { bubbles: true }));
  await tick();
  assert.ok(!cs.classList.contains("copied"), "a rejected clipboard write does not claim success");
  assert.ok(w.getSelection().rangeCount > 0, "the code text is selected as the fallback");
});

test("code-select copy tolerates a null getSelection (still flashes copied)", () => {
  const w = load('<span class="code-select" data-code="x">x</span>', {
    preEval: (win) => { win.getSelection = () => null; },
  });
  const cs = w.document.querySelector(".code-select");
  cs.querySelector(".cbutton").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.ok(cs.classList.contains("copied"), "no selection available -> still marks copied, no throw");
});

test("data-copy button uses the async clipboard API when present", async () => {
  const w = load('<button data-copy="xyz">P</button>', {
    preEval: (win) => { win.navigator.clipboard = { writeText: () => Promise.resolve() }; },
  });
  const b = w.document.querySelector("[data-copy]");
  b.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.ok(b.classList.contains("copied"), "clipboard.writeText success flashes copied");
});

test("print button swallows a throwing window.print", () => {
  const w = load('<button data-action="print">P</button>');
  w.print = () => { throw new Error("no print"); };
  assert.doesNotThrow(() => w.document.querySelector('[data-action="print"]')
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true })),
    "a throwing print is caught, not propagated");
});

// ---- hash -> details / nav + tools toggles --------------------------------------------------

test("openHashDetails opens a <details> that encloses the hash target", () => {
  const w = load('<details id="box"><summary>H</summary><p id="inner">body</p></details>', { hash: "#inner" });
  assert.ok(w.document.getElementById("box").open, "the enclosing details opens for the fragment target");
});

test("nav toggle click handler: nav-link + outside clicks close, other header clicks keep open", () => {
  const w = load('<header class="site-header"><div class="site-header-inner">' +
    '<input type="checkbox" id="nav-toggle" class="nav-toggle">' +
    '<nav class="site-nav"><a href="#x">link</a></nav>' +
    '<span class="brand">B</span></div></header><main>body</main>');
  const cb = w.document.getElementById("nav-toggle");
  cb.checked = true;
  w.document.querySelector(".brand").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, true, "a non-link header click keeps the menu open");
  w.document.querySelector(".site-nav a").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, false, "choosing a nav link closes the menu");
  cb.checked = true;
  w.document.querySelector("main").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, false, "an outside click closes the menu");
  w.document.querySelector("main").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, false, "a click while already closed is a no-op");
});

test("tools supermenu toggle: inside stays open; tools-item link, outside tap and Escape close", () => {
  const w = load('<div class="tools"><input type="checkbox" id="tools-toggle">' +
    '<div class="tools-menu"><a class="tools-item" href="/x">item</a><span class="pad">p</span></div>' +
    '</div><main>out</main>');
  const cb = w.document.getElementById("tools-toggle");
  cb.checked = true;
  w.document.querySelector(".pad").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, true, "a tap inside the menu keeps it open");
  w.document.querySelector("a.tools-item").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, false, "choosing a tools-item closes the menu");
  cb.checked = true;
  w.document.querySelector("main").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, false, "an outside tap closes the menu");
  cb.checked = true;
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.equal(cb.checked, false, "Escape closes the menu");
  w.document.querySelector("main").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(cb.checked, false, "a click while already closed is a no-op");
});

test("back-to-top: click smooth-scrolls to top; scrolling near the top re-hides it", () => {
  let scrolledTop = 0;
  const w = load('<main>x</main><a class="back-to-top" href="#top">Top</a>');
  w.scrollTo = (o) => { if (o && o.top === 0) scrolledTop++; };
  const btn = w.document.querySelector(".back-to-top");
  Object.defineProperty(w, "scrollY", { value: 800, configurable: true });
  w.dispatchEvent(new w.Event("scroll"));
  assert.equal(btn.hidden, false, "revealed past the threshold");
  const ev = new w.MouseEvent("click", { bubbles: true, cancelable: true });
  btn.dispatchEvent(ev);
  assert.ok(ev.defaultPrevented, "click is intercepted");
  assert.equal(scrolledTop, 1, "click smooth-scrolls to the top");
  Object.defineProperty(w, "scrollY", { value: 100, configurable: true });
  w.dispatchEvent(new w.Event("scroll"));
  assert.equal(btn.hidden, true, "re-hidden when scrolled back near the top");
});

// ---- search: root prefix, degradation, Enter/best-match -------------------------------------

test("rootPrefix is empty when no script resembles app.js (search href stays unprefixed)", async () => {
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",
    headExtra: "<script></script>",
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall" }],
  });
  const input = w.document.getElementById("search-input");
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  assert.equal(w.document.querySelector(".search-results li a").getAttribute("href"), "wiki/Firewall",
    "no app.js-like script (and a src-less one) -> empty root prefix");
});

test("search degrades to an empty index when no search-index carrier is present", async () => {
  const w = load('<input id="search-input">');
  const input = w.document.getElementById("search-input");
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  assert.equal(w.document.querySelectorAll(".search-results li").length, 0, "no carrier -> no results, no throw");
});

test("search tolerates a non-ok index fetch (empty index, no throw)", async () => {
  const w = load('<input id="search-input">', { searchIndex: null });  // carrier present, fetch resolves !ok
  const input = w.document.getElementById("search-input");
  input.value = "fire";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  assert.equal(w.document.querySelectorAll(".search-results li").length, 0, "non-ok fetch -> empty index");
});

// location.assign is non-configurable in jsdom (cannot be spied), but a pure-hash target IS
// navigated (jsdom implements hash-only navigation). With root="" (a non-app.js script) the
// best-match href is a bare "#frag", so the Enter navigation is observable as location.hash.
test("search Enter navigates to the best match: exact title beats a substring hit", async () => {
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",   // no app.js match -> rootPrefix "" -> bare-hash hrefs
    searchIndex: [{ t: "Firewall API", u: "#firewall-api" }, { t: "API", u: "#api" }],
  });
  const input = w.document.getElementById("search-input");
  input.focus();
  await tick();
  input.value = "api";
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Enter" }));
  await tick();
  assert.equal(w.location.hash, "#api", "exact (case-insensitive) title match wins over the substring");
});

test("search Enter: substring fallback; short, non-Enter, IME and no-match presses are inert", async () => {
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",
    searchIndex: [{ t: "Firewall", u: "#firewall" }],
  });
  const input = w.document.getElementById("search-input");
  input.focus();
  await tick();
  input.value = "fire";
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Enter" }));
  await tick();
  assert.equal(w.location.hash, "#firewall", "falls back to the first substring match");
  // Reset the observable, then prove every inert case leaves the hash untouched.
  w.location.hash = "#sentinel";
  input.value = "f";                        // sub-2 chars
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Enter" }));
  input.value = "fire";
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "a" }));     // non-Enter
  const ime = new w.KeyboardEvent("keydown", { key: "Enter" });          // IME composition
  Object.defineProperty(ime, "isComposing", { value: true });
  input.dispatchEvent(ime);
  input.value = "zzzznomatch";              // no match -> bestMatch null
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Enter" }));
  await tick();
  assert.equal(w.location.hash, "#sentinel",
    "no navigation from a short query, a non-Enter key, an IME-composing Enter, or a no-match query");
});

test("search hides and clears results for a sub-2-character query", async () => {
  const w = load('<input id="search-input">', { searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }] });
  const input = w.document.getElementById("search-input");
  const results = () => w.document.querySelector(".search-results");
  input.value = "fire"; input.dispatchEvent(new w.Event("input")); await tick();
  assert.equal(results().hidden, false, "results shown for a real query");
  input.value = "f"; input.dispatchEvent(new w.Event("input")); await tick();
  assert.ok(results().hidden && results().children.length === 0, "short query hides and clears the results");
});

// ---- storage resilience (every localStorage access is try/caught) ---------------------------

test("storage failures are swallowed: theme, banners, sitenotice and the viewer all degrade", () => {
  const boom = () => { throw new Error("blocked"); };
  const throwing = { get length() { boom(); }, getItem: boom, setItem: boom, removeItem: boom, clear: boom, key: boom };
  const w = load(
    '<a href="#" data-darkmode>t</a>' +
    '<div class="bottom-stack">' +
    '<input type="checkbox" id="consent-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="consent-banner"><label for="consent-dismiss-cb" data-consent-dismiss>OK</label></div>' +
    '<input type="checkbox" id="stage-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="stage-banner"><label for="stage-dismiss-cb" data-stage-dismiss>OK</label></div>' +
    '</div>' +
    '<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="9">p</div>' +
    '<button data-sitenotice-dismiss>x</button></div>' +
    '<div data-storage-viewer></div>',
    { preEval: (win) => Object.defineProperty(win, "localStorage", { value: throwing, configurable: true }) });
  w.document.querySelector("[data-darkmode]").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.document.documentElement.getAttribute("data-theme"), "dark", "theme flips in-memory despite storage throwing");
  const cc = w.document.getElementById("consent-dismiss-cb"); cc.checked = true;
  assert.doesNotThrow(() => cc.dispatchEvent(new w.Event("change", { bubbles: true })), "consent change swallows the throw");
  const sc = w.document.getElementById("stage-dismiss-cb"); sc.checked = true;
  assert.doesNotThrow(() => sc.dispatchEvent(new w.Event("change", { bubbles: true })), "stage change swallows the throw");
  assert.doesNotThrow(() => w.document.querySelector("[data-sitenotice-dismiss]")
    .dispatchEvent(new w.Event("click", { bubbles: true })), "sitenotice dismiss swallows the throw");
  assert.ok(/unavailable/i.test(w.document.querySelector("[data-storage-viewer]").textContent),
    "the storage viewer reports unavailability instead of crashing");
});

// ---- bottom-stack spacer --------------------------------------------------------------------

test("bottom-stack spacer: recomputed on resize (rAF-coalesced), lifts the back-to-top button", async () => {
  const w = load('<div class="bottom-stack"><div class="stage-banner">s</div></div>' +
    '<a class="back-to-top" href="#top">Top</a>');
  const btt = w.document.querySelector(".back-to-top");
  // two resizes in the same frame: the second must be coalesced (the rAF guard returns early).
  w.dispatchEvent(new w.Event("resize"));
  w.dispatchEvent(new w.Event("resize"));
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(typeof w.document.body.style.paddingBottom, "string", "body padding reserved for the stack");
  assert.ok(/px$/.test(btt.style.bottom), "back-to-top is lifted above the stack");
});

test("bottom-stack remeasure tolerates no stack present (consent banner outside a bottom-stack)", () => {
  // The consent change handler calls remeasure unconditionally; with no .bottom-stack it must
  // collapse to a zero reservation and leave a (missing) back-to-top alone -- no throw.
  const w = load('<input type="checkbox" id="consent-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="consent-banner"><label for="consent-dismiss-cb" data-consent-dismiss>OK</label></div>');
  const cb = w.document.getElementById("consent-dismiss-cb");
  cb.checked = true;
  assert.doesNotThrow(() => cb.dispatchEvent(new w.Event("change", { bubbles: true })));
});

// ---- banner pre-checks ----------------------------------------------------------------------

test("stage banner: a persisted dismissal pre-checks the box on load", () => {
  const w = load('<div class="bottom-stack">' +
    '<input type="checkbox" id="stage-dismiss-cb" class="banner-dismiss-cb">' +
    '<div class="stage-banner"><label for="stage-dismiss-cb" data-stage-dismiss>OK</label></div></div>',
    { storage: { "stage-notice-dismissed": "1" } });
  assert.ok(w.document.getElementById("stage-dismiss-cb").checked, "persisted stage dismissal pre-checks the box");
});

test("sitenotice: inert when there is no banner with a data-banner-id", () => {
  const w = load('<div id="siteNotice"><p>no banner id here</p></div>');
  assert.equal(w.document.getElementById("siteNotice").hidden, false, "no dismissable banner -> left visible, no throw");
});

test("sitenotice: a banner with an empty id still wires dismissal", () => {
  const w = load('<div id="siteNotice"><div class="sitenotice-banner" data-banner-id="">p</div>' +
    '<button data-sitenotice-dismiss>x</button></div>');
  w.document.querySelector("[data-sitenotice-dismiss]").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.equal(w.document.getElementById("siteNotice").hidden, true, "dismiss hides it");
  assert.equal(w.localStorage.getItem("sitenotice-dismissed"), "", "stores the empty id");
});

// ---- fly-in toast: real (non-test) scheduling + close keyboard + transitionend --------------

test("fly-in toast (non-test): December uses the shorter wait; a fresh visitor is scheduled", () => {
  const waits = [];
  const w = load('<div id="fly-in-notification-panel" hidden><button class="close-panel">x</button></div>', {
    preEval: (win) => {
      const R = win.Date;
      win.Date = class extends R { getMonth() { return 11; } };   // December
      win.Date.now = R.now;
      win.setTimeout = (fn, ms) => { waits.push(ms); return 0; };  // capture the schedule, do not fire
    },
  });
  assert.ok(waits.includes(60000), "December schedules the slide-in after the shortened 60s wait");
});

test("fly-in toast (non-test): a recent dismissal suppresses the toast", () => {
  const now = 1700000000000;
  const w = load('<div id="fly-in-notification-panel" hidden><button class="close-panel">x</button></div>', {
    storage: { "flyin-last-dismissed": String(now - 1000) },
    preEval: (win) => { const R = win.Date; win.Date = class extends R {}; win.Date.now = () => now; },
  });
  assert.equal(w.document.getElementById("fly-in-notification-panel").hidden, true,
    "a dismissal within the window keeps the toast hidden (no schedule)");
});

test("fly-in toast: keyboard close (Enter/Space) + transitionend completes the hide", async () => {
  const w = load('<div id="fly-in-notification-panel" hidden><button class="close-panel">x</button></div>' +
    '<div id="fly-in-notification-test-settings" data-waitinseconds="0" ' +
    'data-dismissfordays="3" data-now="1700000500000"></div>');
  await tick();
  const panel = w.document.getElementById("fly-in-notification-panel");
  assert.equal(panel.hidden, false, "shown after the 0s wait");
  const btn = panel.querySelector(".close-panel");
  const enter = new w.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
  btn.dispatchEvent(enter);
  assert.ok(enter.defaultPrevented, "Enter activates the close");
  btn.dispatchEvent(new w.KeyboardEvent("keydown", { key: " ", bubbles: true }));   // Space also closes
  btn.dispatchEvent(new w.KeyboardEvent("keydown", { key: "x", bubbles: true }));    // other keys ignored
  panel.dispatchEvent(new w.Event("transitionend"));
  assert.equal(panel.hidden, true, "transitionend completes the slide-out hide");
});

// ---- modal focus trap + close affordances ---------------------------------------------------

test("modal focus trap: Tab wraps to the first, Shift+Tab wraps to the last focusable", () => {
  const w = load('<button data-modal-open="m1">open</button>' +
    '<div id="m1" class="mini-modal" hidden><div class="underlay"></div>' +
    '<button class="mm-close">x</button><a href="#a">A</a><a href="#b">B</a></div>');
  w.document.querySelector("[data-modal-open]").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const m = w.document.getElementById("m1");
  // jsdom computes no layout, so present the dialog controls as visible (offsetParent !== null).
  const items = [...m.querySelectorAll("button, a[href]")];
  items.forEach((el) => Object.defineProperty(el, "offsetParent", { value: w.document.body, configurable: true }));
  const first = items[0], last = items[items.length - 1];
  last.focus();
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Tab", bubbles: true }));
  assert.equal(w.document.activeElement, first, "Tab from the last focusable wraps to the first");
  first.focus();
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true }));
  assert.equal(w.document.activeElement, last, "Shift+Tab from the first wraps to the last");
  // focus escaped the dialog entirely (onto the opener): Tab pulls it back inside.
  const opener = w.document.querySelector("[data-modal-open]");
  opener.focus();
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Tab", bubbles: true }));
  assert.equal(w.document.activeElement, first, "Tab from outside the dialog is pulled back to the first focusable");
  opener.focus();
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true }));
  assert.equal(w.document.activeElement, last, "Shift+Tab from outside is pulled back to the last focusable");
});

test("modal focus trap: a dialog with no visible focusables keeps Tab contained", () => {
  const w = load('<button data-modal-open="m1">open</button>' +
    '<div id="m1" class="mini-modal" hidden><div class="underlay"></div><p>text only</p></div>');
  w.document.querySelector("[data-modal-open]").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const ev = new w.KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
  assert.doesNotThrow(() => w.document.dispatchEvent(ev));
  assert.ok(ev.defaultPrevented, "Tab is contained even with nothing focusable");
});

test("modal: underlay click and close-button click both dismiss; a missing target is a no-op", () => {
  const w = load('<button data-modal-open="m1">open</button>' +
    '<button data-modal-open="ghost">bad</button>' +
    '<div id="m1" class="mini-modal" hidden><div class="underlay"></div><button class="mm-close">x</button></div>');
  const m = w.document.getElementById("m1");
  const openM1 = () => w.document.querySelector('[data-modal-open="m1"]')
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  openM1();
  m.querySelector(".underlay").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.ok(!m.classList.contains("active"), "underlay click closes");
  openM1();
  m.querySelector(".mm-close").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.ok(!m.classList.contains("active"), "close-button click closes");
  // a trigger whose target id does not exist opens nothing (open(null) early return)
  assert.doesNotThrow(() => w.document.querySelector('[data-modal-open="ghost"]')
    .dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true })));
});

test("modal: opening a second modal closes the first (one at a time)", () => {
  const w = load('<button data-modal-open="m1">1</button><button data-modal-open="m2">2</button>' +
    '<div id="m1" class="mini-modal" hidden><button class="mm-close">x</button></div>' +
    '<div id="m2" class="mini-modal" hidden><button class="mm-close">x</button></div>');
  w.document.querySelector('[data-modal-open="m1"]').dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.ok(w.document.getElementById("m1").classList.contains("active"));
  w.document.querySelector('[data-modal-open="m2"]').dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.ok(!w.document.getElementById("m1").classList.contains("active"), "first modal closed");
  assert.ok(w.document.getElementById("m2").classList.contains("active"), "second modal open");
});

// ---- download modal: href guard, filename decode, countdown --------------------------------

test("download modal: a blank href is ignored (no modal)", () => {
  const w = load('<a class="download-button-v2 dlbtn-modal" href="">Get</a>');
  w.document.querySelector("a.dlbtn-modal").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.document.getElementById("download-button-modal"), null, "no modal for a blank href");
});

test("download modal: an undecodable filename falls back to the raw href (no throw)", () => {
  const w = load('<a class="download-button-v2 dlbtn-modal" href="/files/bad%E0%A4%A.iso">Get</a>');
  w.document.querySelector("a.dlbtn-modal").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const modal = w.document.getElementById("download-button-modal");
  assert.ok(modal, "modal still opens despite the undecodable name");
  assert.ok(/bad/.test(modal.querySelector(".dl-filename").textContent), "shows the raw filename as a fallback");
});

test("download modal: countdown ticks, pauses while hidden, and proceeds at zero", () => {
  let captured = null;
  const w = load('<a class="download-button-v2 dlbtn-modal" href="https://dl.test/f.iso">Get</a>', {
    preEval: (win) => {
      win.setInterval = (fn) => { captured = fn; return 1; };
      win.clearInterval = () => {};
    },
  });
  w.document.querySelector("a.dlbtn-modal").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const modal = w.document.getElementById("download-button-modal");
  const count = modal.querySelector(".dl-count");
  let proceeded = 0;
  modal.querySelector(".dl-proceed").click = () => { proceeded++; };
  assert.ok(captured, "a countdown interval was scheduled");
  // tab hidden: the tick is a no-op (countdown paused)
  Object.defineProperty(w.document, "hidden", { value: true, configurable: true });
  captured();
  assert.equal(count.textContent, "5", "no decrement while the tab is hidden");
  // tab visible: it counts 5 -> 0 then clicks through to proceed
  Object.defineProperty(w.document, "hidden", { value: false, configurable: true });
  for (let i = 0; i < 5; i++) captured();
  assert.equal(proceeded, 1, "reaching zero clicks the proceed link (rel=noreferrer navigation)");
});

// ---- tabs: skipped controllers, href encoding edges, label stripping, keyboard --------------

test("tab controller is skipped when it has no sections or no mininav", () => {
  const w = load('<div class="tab-content-controller"><div class="tcc-content"></div></div>');
  assert.equal(w.document.querySelector(".mininav"), null, "nothing built for a controller with no mininav/sections");
});

test("tab pill: no heading id -> href '#'; a tcc-image img is adopted; share/edit affordances stripped from the label", () => {
  const w = load('<div class="tab-content-controller"><div class="mininav"></div><div class="tcc-content">' +
    '<div class="tcc-section"><div class="tcc-image"><img src="i.webp" alt="I"></div>' +
    '<div class="tcc-title"><h3>Plain<span class="share-tooltip">S</span><span class="mw-editsection">E</span></h3></div>' +
    '</div></div></div>');
  const pill = w.document.querySelector(".mininav .tcc-tab");
  assert.equal(pill.getAttribute("href"), "#", "a section with no heading id gets a '#' pill href");
  assert.ok(pill.querySelector("img"), "the tcc-image img is adopted into the pill");
  assert.equal(pill.textContent.trim(), "Plain", "share-tooltip and mw-editsection are stripped from the pill label");
});

test("tab click falls back to location.hash when history.replaceState throws", () => {
  const w = load('<div class="tab-content-controller"><div class="mininav"></div><div class="tcc-content">' +
    '<div class="tcc-section"><div class="tcc-title"><h3 id="one">One</h3></div></div>' +
    '<div class="tcc-section"><div class="tcc-title"><h3 id="two">Two</h3></div></div></div></div>', {
    preEval: (win) => { win.history.replaceState = () => { throw new Error("blocked"); }; },
  });
  const pills = w.document.querySelectorAll(".mininav .tcc-tab");
  pills[1].dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.location.hash, "#two", "a throwing replaceState falls back to setting location.hash");
});

test("tab keyboard: ArrowLeft and Home move/activate; a non-navigation key is ignored", () => {
  const body = '<div class="tab-content-controller"><div class="mininav"></div><div class="tcc-content">' +
    '<div class="tcc-section active"><div class="tcc-title"><h3 id="a">A</h3></div></div>' +
    '<div class="tcc-section"><div class="tcc-title"><h3 id="b">B</h3></div></div>' +
    '<div class="tcc-section"><div class="tcc-title"><h3 id="c">C</h3></div></div></div></div>';
  const w = load(body);
  const ul = w.document.querySelector(".mininav > ul");
  const secs = w.document.querySelectorAll(".tcc-content > .tcc-section");
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
  assert.ok(secs[2].classList.contains("active"), "ArrowLeft from the first wraps to the last");
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Home", bubbles: true }));
  assert.ok(secs[0].classList.contains("active"), "Home activates the first tab");
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "z", bubbles: true }));
  assert.ok(secs[0].classList.contains("active"), "a non-navigation key leaves the selection unchanged");
});

test("syncTabsFromHash activates nested tab sections for a deep fragment", () => {
  const w = load('<div class="tab-content-controller" id="outer"><div class="mininav"></div>' +
    '<div class="tcc-content">' +
    '<div class="tcc-section" id="os1"><div class="tcc-title"><h3 id="o1">O1</h3></div>' +
    '<div class="tab-content-controller" id="inner"><div class="mininav"></div><div class="tcc-content">' +
    '<div class="tcc-section" id="is1"><div class="tcc-title"><h3 id="i1">I1</h3></div></div>' +
    '<div class="tcc-section" id="is2"><div class="tcc-title"><h3 id="deep">Deep</h3></div></div>' +
    '</div></div></div>' +
    '<div class="tcc-section" id="os2"><div class="tcc-title"><h3 id="o2">O2</h3></div></div>' +
    '</div></div>', { hash: "#deep" });
  // openHashDetails/syncTabsFromHash ran at load for #deep: both the outer section holding the
  // inner controller AND the inner target section are activated (outermost first).
  assert.ok(w.document.getElementById("os1").classList.contains("active"), "the outer section is activated");
  assert.ok(w.document.getElementById("is2").classList.contains("active"), "the nested target section is activated");
});

test("search Enter skips a namespaced entry for a plain query (bestMatch ns filter)", async () => {
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",
    searchIndex: [{ t: "Template:Box", u: "#tmpl", n: 1 }, { t: "Box", u: "#box" }],
  });
  const input = w.document.getElementById("search-input");
  input.focus();
  await tick();
  input.value = "box";
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Enter" }));
  await tick();
  assert.equal(w.location.hash, "#box", "a plain query skips the namespaced entry, landing on the main-namespace page");
});

// ---- hovercards: reference edge cases + dismissal + page-preview guards ----------------------

test("hovercards: citation edge cases (empty/missing/external) show no card; mouseout dismisses", async () => {
  const w = load('<div class="wiki-content">' +
    '<sup class="reference"><a href="#">bad</a></sup>' +
    '<sup class="reference"><a href="#nope">gone</a></sup>' +
    '<sup class="reference"><a href="https://ext/">ext</a></sup>' +
    '<sup class="reference"><a href="#fn1">[1]</a></sup>' +
    '<li id="fn1">Real note.</li></div>');
  const content = w.document.querySelector(".wiki-content");
  const sups = w.document.querySelectorAll("sup.reference a");
  const dwell = () => new Promise((r) => setTimeout(r, 240));
  content.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));   // non-anchor target: ignored
  sups[0].dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true })); await dwell();
  assert.equal(w.document.querySelector(".hovercard-ref"), null, "empty-id citation -> no card");
  sups[1].dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true })); await dwell();
  assert.equal(w.document.querySelector(".hovercard-ref"), null, "missing-target citation -> no card");
  sups[2].dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true })); await dwell();
  assert.equal(w.document.querySelector(".hovercard-ref"), null, "external-href citation -> no card");
  sups[3].dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true })); await dwell();
  const card = w.document.querySelector(".hovercard");
  assert.ok(/Real note/.test(card.textContent), "a resolvable citation opens");
  content.dispatchEvent(new w.MouseEvent("mouseout", { bubbles: true }));
  await dwell();
  assert.ok(card.hidden, "mouseout hides the card after the dwell");
});

test("hovercards: page-preview guards (external/protocol-relative/no-summary/hash/undecodable); title falls back to key", async () => {
  const w = load('<div class="wiki-content">' +
    '<a id="ext" href="https://evil/wiki/Firewall/">x</a>' +
    '<a id="proto" href="//cdn/wiki/Firewall/">x</a>' +
    '<a id="nosum" href="NoSummary/">x</a>' +
    '<a id="badpct" href="Bad%E0%A4%A/">x</a>' +
    '<a id="hashonly" href="#frag">x</a>' +
    '<a id="ok" href="Firewall/">x</a></div>',
    { appSrc: "../app.min.js",
      previews: { "wiki/Firewall/": { d: "Blocks traffic." }, "wiki/NoSummary/": { t: "NS" } } });
  const hover = (id) => w.document.getElementById(id).dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  const settle = async () => { await tick(); await new Promise((r) => setTimeout(r, 230)); };
  for (const id of ["ext", "proto", "nosum", "badpct", "hashonly"]) {
    hover(id); await settle();
    assert.equal(w.document.querySelector(".hovercard-page"), null, id + " -> no page card");
  }
  hover("ok"); await settle();
  const card = w.document.querySelector(".hovercard-page");
  assert.ok(card && /Blocks traffic/.test(card.textContent), "a resolvable internal link shows its summary");
  assert.ok(/Firewall/.test(card.querySelector(".hovercard-title").textContent), "title falls back to the key when t is absent");
});

test("hovercards: a link resolving outside the output root shows no card", async () => {
  const w = load('<div class="wiki-content"><a id="out" href="Other/">x</a></div>',
    { appSrc: "../../vendor-bundle.js",   // root "" -> rootUrl is this very page, siblings are "outside"
      previews: { "Other/": { t: "O", d: "d" } } });
  w.document.getElementById("out").dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await tick();
  await new Promise((r) => setTimeout(r, 230));
  assert.equal(w.document.querySelector(".hovercard-page"), null, "a sibling outside the computed root is skipped");
});

test("hovercards: previews fetch that resolves before the pointer leaves vs after", async () => {
  const w = load('<div class="wiki-content"><a id="a" href="Firewall/">x</a><a id="b" href="Tor/">y</a></div>',
    { appSrc: "../app.min.js",
      previews: { "wiki/Firewall/": { t: "Firewall", d: "FW." } } });
  const a = w.document.getElementById("a");
  // enter a, then immediately leave (pointer moves to b) before the fetch resolves -> no stale card
  a.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  w.document.querySelector(".wiki-content").dispatchEvent(new w.MouseEvent("mouseout", { bubbles: true }));
  await tick();
  await new Promise((r) => setTimeout(r, 230));
  assert.equal(w.document.querySelector(".hovercard-page"), null, "a preview that lands after the pointer left shows nothing");
});

// ---- storage viewer: unrecognized key + per-item delete -------------------------------------

test("storage viewer: lists an unrecognized key and a per-item Delete removes just that key", () => {
  const w = load('<div data-storage-viewer></div>',
    { storage: { "theme": "dark", "some-mystery-key": "v1" } });
  const mount = w.document.querySelector("[data-storage-viewer]");
  assert.ok(/some-mystery-key/.test(mount.textContent), "an unrecognized stored key is surfaced");
  assert.ok(/unrecognized/i.test(mount.textContent), "it is labelled unrecognized");
  // click the Delete for the first set key, then confirm storage shrank + re-rendered
  const before = w.localStorage.length;
  mount.querySelector(".storage-del").dispatchEvent(new w.Event("click", { bubbles: true }));
  assert.ok(w.localStorage.length < before, "the per-item Delete removed exactly one key");
  assert.ok(/Deleted/.test(mount.textContent), "the viewer re-renders with a 'Deleted' note");
});

// ---- wide tables: resize fallback, scroll-sync lock, fits-after-overwide --------------------

test("wide tables: without ResizeObserver, build via sync() and re-sync on a coalesced resize", async () => {
  const w = load('<div class="wiki-content"><table id="wide"><tbody><tr><td>x</td></tr></tbody></table></div>', {
    preEval: (win) => { win.ResizeObserver = undefined; },
  });
  const wide = w.document.getElementById("wide");
  // geometry is read during the deferred sync(); stub it so the table reads as overwide.
  stubTableGeom(w.document, wide, 400, 200);
  w.dispatchEvent(new w.Event("resize"));
  w.dispatchEvent(new w.Event("resize"));   // coalesced by the rAF guard
  await new Promise((r) => setTimeout(r, 30));
  const rail = wide.previousElementSibling;
  assert.ok(rail && rail.classList.contains("table-scroll-top"), "the fallback built the top rail on resize");
});

test("wide tables: the top rail and the table mirror each other's scrollLeft (re-entrancy guarded)", () => {
  const w = load('<div class="wiki-content"><table id="wide"><tbody><tr><td>x</td></tr></tbody></table></div>');
  const wide = w.document.getElementById("wide");
  stubTableGeom(w.document, wide, 400, 200);
  w.__resizeObservers[0].cb();   // build the rail
  const rail = wide.previousElementSibling;
  // Setting scrollLeft normally fires no scroll event in jsdom; make it do so, which also
  // re-enters the sibling's handler while the sync lock is held (exercising the lock guard).
  const reflect = (el) => {
    let v = 0;
    Object.defineProperty(el, "scrollLeft", {
      configurable: true,
      get() { return v; },
      set(n) { v = n; el.dispatchEvent(new w.Event("scroll")); },
    });
  };
  reflect(rail); reflect(wide);
  wide.scrollLeft = 123;
  assert.equal(rail.scrollLeft, 123, "scrolling the table syncs the rail");
  rail.scrollLeft = 45;
  assert.equal(wide.scrollLeft, 45, "scrolling the rail syncs the table");
});

test("wide tables: a rail-bearing table that later fits is hidden again", () => {
  const w = load('<div class="wiki-content"><table id="wide"><tbody><tr><td>x</td></tr></tbody></table></div>');
  const wide = w.document.getElementById("wide");
  const geom = { sw: 400, cw: 200 };
  Object.defineProperty(wide, "scrollWidth", { configurable: true, get() { return geom.sw; } });
  Object.defineProperty(wide, "clientWidth", { configurable: true, get() { return geom.cw; } });
  const ro = w.__resizeObservers[0];
  ro.cb();   // overwide -> builds + shows the rail
  const rail = wide.previousElementSibling;
  assert.equal(rail.style.display, "", "rail shown while overwide");
  geom.sw = 150;   // now it fits
  ro.cb();
  assert.equal(rail.style.display, "none", "rail hidden once the table fits");
  assert.equal(wide.style.marginTop, "", "the overwide pin is released");
});

// ---- gallery lightbox: defensive unwrapped thumb, skipped boxes, caption + keys --------------

test("gallery lightbox: an unwrapped thumb is made its own trigger (click + Enter open)", () => {
  const w = load('<div class="gallery">' +
    '<span class="gallerybox"><span class="thumb"></span></span>' +        // no img -> skipped
    '<span class="gallerybox"><span class="thumb"><img src="solo.webp" alt="Solo"></span></span>' +  // no <a>, no caption -> alt caption
    '</div>');
  const img = w.document.querySelector(".gallery img");
  assert.ok(img.classList.contains("glb-thumb"), "the unwrapped thumb is marked glb-thumb");
  assert.equal(img.getAttribute("role"), "button", "and exposed as a button");
  const click = new w.MouseEvent("click", { bubbles: true, cancelable: true });
  img.dispatchEvent(click);
  assert.ok(click.defaultPrevented, "clicking the thumb opens the lightbox (prevents default)");
  let lb = w.document.querySelector(".gallery-lightbox.active");
  assert.ok(lb, "lightbox opened on click");
  assert.equal(lb.querySelector(".glb-caption").textContent, "Solo", "caption falls back to the img alt");
  // close, then re-open via keyboard Enter on the thumb
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  const key = new w.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
  img.dispatchEvent(key);
  assert.ok(key.defaultPrevented, "Enter on the thumb opens the lightbox");
  assert.ok(w.document.querySelector(".gallery-lightbox.active"), "lightbox re-opened via keyboard");
});

test("gallery lightbox: ArrowLeft pages backward and the overlay closes cleanly", () => {
  const w = load('<div class="gallery">' +
    '<span class="gallerybox"><a class="glb-link" href="a.webp"><span class="thumb"><img src="a.webp" alt="A"></span></a></span>' +
    '<span class="gallerybox"><a class="glb-link" href="b.webp"><span class="thumb"><img src="b.webp" alt="B"></span></a></span>' +
    '</div>');
  const first = w.document.querySelector(".gallery .gallerybox > a.glb-link");
  first.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const lb = w.document.querySelector(".gallery-lightbox");
  assert.equal(lb.querySelector(".glb-image").getAttribute("src"), "a.webp", "opened at the first image");
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
  assert.equal(lb.querySelector(".glb-image").getAttribute("src"), "b.webp", "ArrowLeft wraps backward to the last");
  // Escape closes: the onClose callback removes the keydown listener + the modal node
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.ok(!w.document.querySelector(".gallery-lightbox"), "closing removes the lightbox node");
});

// ---- nav keyboard: top Home/End/Escape, submenu motion, no-submenu top, focusout -------------

const NAV3 = '<header><nav class="site-nav"><ul>' +
  '<li class="nav-group"><a class="nav-top" href="/a">A</a><ul class="nav-submenu">' +
  '<li><a href="/a1">A1</a></li><li><a href="/a2">A2</a></li></ul></li>' +
  '<li class="nav-group"><a class="nav-top" href="/b">B</a><ul class="nav-submenu">' +
  '<li><a href="/b1">B1</a></li></ul></li>' +
  '<li><a class="nav-top" href="/c">C</a></li></ul></nav></header>';

test("nav keyboard: Home/End jump between top items and Escape on a top item is inert-safe", () => {
  const w = load(NAV3);
  const tops = [...w.document.querySelectorAll(".site-nav > ul > li > .nav-top")];
  const key = (el, k) => el.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true }));
  tops[0].focus();
  key(tops[0], "End");
  assert.equal(tops[2].tabIndex, 0, "End moves roving focus to the last top item");
  key(tops[2], "Home");
  assert.equal(tops[0].tabIndex, 0, "Home moves roving focus to the first top item");
  assert.doesNotThrow(() => key(tops[0], "Escape"), "Escape on a top item does not throw");
});

test("nav keyboard: a top item with no submenu does not open, and within-submenu arrows/Home/End move", () => {
  const w = load(NAV3);
  const tops = [...w.document.querySelectorAll(".site-nav > ul > li > .nav-top")];
  const key = (el, k) => el.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true }));
  // the submenu-less top item: ArrowDown must not throw and sets no kb-open
  tops[2].focus();
  key(tops[2], "ArrowDown");
  assert.ok(!tops[2].closest("li").classList.contains("kb-open"), "a submenu-less top item does not open");
  // open the first group's submenu and walk it with Home/End/Arrows, then move groups with ArrowRight
  tops[0].focus();
  key(tops[0], "ArrowDown");
  const subA = [...w.document.querySelectorAll(".nav-group .nav-submenu")][0].querySelectorAll("a");
  key(w.document.activeElement, "End");
  assert.equal(w.document.activeElement, subA[1], "End focuses the last submenu item");
  key(w.document.activeElement, "Home");
  assert.equal(w.document.activeElement, subA[0], "Home focuses the first submenu item");
  key(w.document.activeElement, "ArrowUp");  // from the first item, Up closes + returns to the top
  assert.equal(w.document.activeElement, tops[0], "ArrowUp from the first item returns to the top");
  // ArrowRight from within a submenu opens the next group's submenu
  key(tops[0], "ArrowDown");
  key(w.document.activeElement, "ArrowRight");
  assert.ok(tops[1].closest("li").classList.contains("kb-open"), "ArrowRight opens the next group's submenu");
  key(w.document.activeElement, "ArrowLeft");
  assert.ok(tops[0].closest("li").classList.contains("kb-open"), "ArrowLeft opens the previous group's submenu");
});

test("nav keyboard: focusout to outside the bar closes any open submenu", () => {
  const w = load(NAV3);
  const tops = [...w.document.querySelectorAll(".site-nav > ul > li > .nav-top")];
  const nav = w.document.querySelector(".site-nav > ul");
  tops[0].focus();
  tops[0].dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
  assert.ok(tops[0].closest("li").classList.contains("kb-open"), "submenu open");
  // focus leaves the nav entirely (relatedTarget outside) -> closeAll
  const out = w.document.querySelector("header");
  nav.dispatchEvent(new w.FocusEvent("focusout", { bubbles: true, relatedTarget: out }));
  assert.ok(!tops[0].closest("li").classList.contains("kb-open"), "leaving the bar closes the submenu");
});

// ---- remaining edge branches ----------------------------------------------------------------

test("openHashDetails tolerates a hash target that lacks .closest (no throw)", () => {
  const w = load('<p id="t">x</p>');
  const el = w.document.getElementById("t");
  Object.defineProperty(el, "closest", { value: undefined, configurable: true });
  w.location.hash = "#t";
  assert.doesNotThrow(() => w.dispatchEvent(new w.Event("hashchange")), "no .closest -> treated as no enclosing details");
});

test("syncTabsFromHash scrolls the target into view and skips a controller-less .tcc-section", () => {
  const w = load('<div class="tcc-section" id="stray"><div class="tcc-title"><h3 id="s">S</h3></div></div>', { hash: "#stray" });
  const el = w.document.getElementById("stray");
  let scrolled = 0;
  el.scrollIntoView = () => { scrolled++; };
  w.dispatchEvent(new w.Event("hashchange"));
  assert.ok(scrolled >= 1, "the fragment target is scrolled into view (no controller to activate)");
});

test("bottom-stack: a measured stack height lifts the back-to-top above it", async () => {
  const w = load('<div class="bottom-stack"><div class="stage-banner">s</div></div>' +
    '<a class="back-to-top" href="#top">Top</a>');
  const stack = w.document.querySelector(".bottom-stack");
  Object.defineProperty(stack, "offsetHeight", { value: 50, configurable: true });
  w.dispatchEvent(new w.Event("resize"));
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(w.document.querySelector(".back-to-top").style.bottom, "70px", "back-to-top sits 20px above the 50px stack");
});

test("fly-in tolerates storage failures on both the dismissal read and the dismissal write", async () => {
  const boom = () => { throw new Error("blocked"); };
  const throwing = { get length() { boom(); }, getItem: boom, setItem: boom, removeItem: boom, clear: boom, key: boom };
  // non-test panel: the dismissal READ throws and is swallowed; load() itself returning proves no crash.
  const w1 = load('<div id="fly-in-notification-panel" hidden><button class="close-panel">x</button></div>', {
    preEval: (win) => Object.defineProperty(win, "localStorage", { value: throwing, configurable: true }),
  });
  assert.equal(w1.document.getElementById("fly-in-notification-panel").hidden, true, "init survived the throwing read");
  // test-settings panel shows immediately; closing it has its dismissal WRITE throw, swallowed.
  const w2 = load('<div id="fly-in-notification-panel" hidden><button class="close-panel">x</button></div>' +
    '<div id="fly-in-notification-test-settings" data-waitinseconds="0" data-now="1700000000000"></div>', {
    preEval: (win) => Object.defineProperty(win, "localStorage", { value: throwing, configurable: true }),
  });
  await tick();
  const panel = w2.document.getElementById("fly-in-notification-panel");
  assert.equal(panel.hidden, false, "shown despite storage being unavailable");
  assert.doesNotThrow(() => panel.querySelector(".close-panel").dispatchEvent(new w2.Event("click", { bubbles: true })),
    "the dismissal write throw is swallowed on close");
});

test("download modal: a trailing-slash href falls back to the full href as the filename", () => {
  const w = load('<a class="download-button-v2 dlbtn-modal" href="https://dl.test/dir/">Get</a>');
  w.document.querySelector("a.dlbtn-modal").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const modal = w.document.getElementById("download-button-modal");
  assert.ok(/dl\.test\/dir\//.test(modal.querySelector(".dl-filename").textContent),
    "an empty basename falls back to showing the full href");
});

test("hovercards: with no previews carrier the index resolves to empty (no card, no throw)", async () => {
  const w = load('<div class="wiki-content"><a href="Firewall/">Firewall</a></div>', { appSrc: "../app.min.js" });
  w.document.querySelector(".wiki-content a").dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await tick();
  await new Promise((r) => setTimeout(r, 230));
  assert.equal(w.document.querySelector(".hovercard-page"), null, "no carrier -> empty index -> no page card");
});

test("storage viewer: per-item Delete and Delete-all swallow a throwing remove/clear", () => {
  const boom = () => { throw new Error("blocked"); };
  const backing = { theme: "dark" };
  const keys = Object.keys(backing);
  const storage = {
    get length() { return keys.length; },
    key(i) { return keys[i]; },
    getItem(k) { return k in backing ? backing[k] : null; },
    setItem() {}, removeItem: boom, clear: boom,
  };
  const w = load('<div data-storage-viewer></div>', {
    preEval: (win) => Object.defineProperty(win, "localStorage", { value: storage, configurable: true }),
  });
  const mount = w.document.querySelector("[data-storage-viewer]");
  assert.ok(mount.querySelector(".storage-del"), "rows render with a Delete button");
  assert.doesNotThrow(() => mount.querySelector(".storage-del").dispatchEvent(new w.Event("click", { bubbles: true })),
    "a throwing removeItem is swallowed, viewer re-renders");
  assert.doesNotThrow(() => mount.querySelector(".storage-clear").dispatchEvent(new w.Event("click", { bubbles: true })),
    "a throwing clear is swallowed, viewer re-renders");
});

test("gallery lightbox: a thumb with no caption/alt/src yields empty strings; Space opens it", () => {
  const w = load('<div class="gallery"><span class="gallerybox"><span class="thumb"><img></span></span></div>');
  const img = w.document.querySelector(".gallery img");
  const key = new w.KeyboardEvent("keydown", { key: " ", bubbles: true, cancelable: true });
  img.dispatchEvent(key);
  assert.ok(key.defaultPrevented, "Space on the thumb opens the lightbox");
  const lb = w.document.querySelector(".gallery-lightbox.active");
  assert.ok(lb, "lightbox opened");
  assert.equal(lb.querySelector(".glb-image").getAttribute("src"), "", "no src -> empty image src");
  assert.equal(lb.querySelector(".glb-caption").textContent, "", "no caption or alt -> empty caption");
});

test("nav keyboard: a keydown on the bar itself is inert; ArrowDown/ArrowUp(mid)/ArrowRight-to-plain in a submenu", () => {
  const w = load(NAV3);
  const nav = w.document.querySelector(".site-nav > ul");
  const tops = [...nav.querySelectorAll(":scope > li > .nav-top")];
  const key = (el, k) => el.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true }));
  assert.doesNotThrow(() => nav.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true })),
    "a keydown whose target is neither a top item nor a submenu link is ignored");
  tops[0].focus();
  key(tops[0], "ArrowDown");
  const subA = [...nav.querySelectorAll(".nav-group .nav-submenu")][0].querySelectorAll("a");
  assert.equal(w.document.activeElement, subA[0], "first submenu item focused");
  key(w.document.activeElement, "ArrowDown");
  assert.equal(w.document.activeElement, subA[1], "ArrowDown moves to the next submenu item");
  key(w.document.activeElement, "ArrowUp");
  assert.equal(w.document.activeElement, subA[0], "ArrowUp from a mid item moves up one (not back to the top)");
  key(tops[1], "ArrowDown");
  key(w.document.activeElement, "ArrowRight");
  assert.equal(w.document.activeElement, tops[2], "ArrowRight to a submenu-less group focuses that top item");
});

// ---- full-text search: sharded inverted index + BM25/proximity scorer -----------------------
// The parity block is the HARD cross-language gate: app.js's OWN tokenizer/hash (window.mwSearch)
// must reproduce mwstatic/tests/fixtures/search-parity.json byte-for-byte -- the SAME fixture the
// Python indexer test asserts against. A drift in either language fails its lane.
// Intentionally UNGUARDED: the fixture co-ships with this suite, so a missing one is a packaging
// bug that MUST fail loud here (a plain ENOENT) -- do NOT add a top-level `if (!existsSync) return`
// self-skip: this is NOT the tail (28 test()s follow, ~18 fixture-INDEPENDENT), so a module-top
// return would silently DROP them -> a fabricated green, worse than a loud ENOENT.
const FX = JSON.parse(readFileSync(
  path.join(__dirname, "fixtures/search-parity.json"),   // co-located in dist-ai jscov/fixtures/
  "utf8"));
const pad3 = (n) => ("00" + n).slice(-3);
const bktOf = (() => { const m = {}; FX.hash.forEach(([t, _h, b]) => { m[t] = b; }); return m; })();

test("search primitives reproduce the Python parity fixture exactly (cross-language gate)", () => {
  const S = load("<main>x</main>").mwSearch;
  assert.ok(S && S.tokenize && S.ftHash && S.ftBucket, "mwSearch primitives exposed");
  // Compare via JSON: tokenize/Object.keys return arrays from the jsdom realm, whose Array
  // prototype differs from node's, so assert.deepEqual (strict) would reject equal-content arrays.
  assert.equal(JSON.stringify(Object.keys(S.stopwords).sort()), JSON.stringify(FX.stopwords),
    "STOPWORDS identical to Python");
  for (const [src, expected] of FX.tokenize) {
    assert.equal(JSON.stringify(S.tokenize(src)), JSON.stringify(expected),
      "tokenize parity: " + JSON.stringify(src));
  }
  for (const [term, h, b] of FX.hash) {
    assert.equal(S.ftHash(term), h, "ftHash parity: " + term);
    assert.equal(S.ftBucket(term, FX.buckets), b, "ftBucket parity: " + term);
  }
});

test("scoreBM25: title boost, proximity bonus, and AND-intersection", () => {
  const score = load("<main>x</main>").mwSearch.score;
  // title boost: page 1 carries the term in its title (titleTf 1) -> ranks above body-only page 0.
  const r1 = score({ docs: 2, avgdl: 10, dl: [10, 10] }, ["tor"], [[[0, 0, [5]], [1, 1, [5]]]]);
  assert.equal(r1[0][0], 1, "title-boosted page ranks first");
  // proximity: terms adjacent (abs 2 then 3) on page 0, scattered (2, 9) on page 1 -> page 0 wins.
  const r2 = score({ docs: 2, avgdl: 4, dl: [4, 4] }, ["a", "b"],
    [[[0, 0, [2]], [1, 0, [2]]], [[0, 0, [3]], [1, 0, [9]]]]);
  assert.equal(r2[0][0], 0, "adjacent-term page wins on the proximity bonus");
  // AND: a page present in only one term's list is excluded from the intersection.
  const r3 = score({ docs: 3, avgdl: 5, dl: [5, 5, 5] }, ["a", "b"],
    [[[0, 0, [1]], [1, 0, [1]]], [[0, 0, [1]], [2, 0, [1]]]]);
  assert.equal(JSON.stringify(r3.map((x) => x[0])), "[0]", "only the page in BOTH term lists survives");
});

test("full-text appends body-only matches after title hits, BM25-ranked", async () => {
  const name = pad3(bktOf.anonymity);
  const shard = {}; shard[name] = { anonymity: [[1, 0, [5]], [2, 0, [2]]] };
  const sh = {}; sh[name] = "abc12345";
  const w = load('<input id="search-input">', {
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }, { t: "Tor", u: "wiki/Tor/" },
                  { t: "Networking Guide", u: "wiki/Networking_Guide/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 3, avgdl: 53.33, dl: [50, 10, 100],
                base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "anonymity";                   // no title contains it -> title pass renders nothing
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const links = [...w.document.querySelectorAll(".search-results li a")].map((a) => a.textContent);
  assert.deepEqual(links, ["Tor", "Networking Guide"],
    "body-only matches appended; shorter doc (Tor, dl 10) outranks the longer (dl 100)");
});

test("full-text merges with title hits without double-listing a page", async () => {
  const name = pad3(bktOf.tor);
  const shard = {}; shard[name] = { tor: [[0, 0, [3]], [1, 1, [0]]] };  // page0 body, page1 title+body
  const sh = {}; sh[name] = "deadbeef";
  const w = load('<input id="search-input">', {
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }, { t: "Tor", u: "wiki/Tor/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 2, avgdl: 20, dl: [30, 10], base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "tor";
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const links = [...w.document.querySelectorAll(".search-results li a")].map((a) => a.textContent);
  assert.deepEqual(links, ["Tor", "Firewall"],
    "title hit Tor first, then body-only Firewall; Tor (already shown) not duplicated");
});

test("a namespace-qualified query stays title-only (full-text skipped)", async () => {
  const name = pad3(bktOf.tor);
  const shard = {}; shard[name] = { tor: [[0, 0, [1]]] };   // Homepage body has 'tor'
  const sh = {}; sh[name] = "cafe0001";
  const w = load('<input id="search-input">', {
    searchIndex: [{ t: "Homepage", u: "" }, { t: "Template:Tor", u: "wiki/Template:Tor/", n: 1 }],
    manifest: { v: 1, buckets: FX.buckets, docs: 1, avgdl: 10, dl: [10, 0], base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "template:tor";
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const links = [...w.document.querySelectorAll(".search-results li a")].map((a) => a.textContent);
  assert.deepEqual(links, ["Template:Tor"],
    "only the namespaced title hit; the body (Homepage) match is NOT appended");
});

test("full-text degrades gracefully on a shard miss and an empty bucket", async () => {
  const name = pad3(bktOf.anonymity);
  // Case A: sh advertises the bucket but the shard body is not served (fetch ok:false -> null).
  const shMiss = {}; shMiss[name] = "11112222";
  const wA = load('<input id="search-input">', {
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 1, avgdl: 10, dl: [10], base: "search/ft/", sh: shMiss },
    shards: {},
  });
  const iA = wA.document.getElementById("search-input");
  iA.value = "anonymity";
  iA.dispatchEvent(new wA.Event("input"));
  await tick(); await tick();
  assert.equal(wA.document.querySelectorAll(".search-results li a").length, 0,
    "shard miss -> no results, no throw");
  // Case B: the term's bucket is absent from sh -> ensureShard returns null WITHOUT fetching.
  const wB = load('<input id="search-input">', {
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 1, avgdl: 10, dl: [10], base: "search/ft/", sh: {} },
    shards: {},
  });
  const iB = wB.document.getElementById("search-input");
  iB.value = "anonymity";
  iB.dispatchEvent(new wB.Event("input"));
  await tick(); await tick();
  assert.equal(wB.document.querySelectorAll(".search-results li a").length, 0,
    "empty bucket -> no results");
});

test("a <2-char query renders nothing (full-text never runs)", async () => {
  const w = load('<input id="search-input">', {
    searchIndex: [{ t: "Tor", u: "wiki/Tor/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 1, avgdl: 5, dl: [5], base: "search/ft/", sh: {} },
    shards: {},
  });
  const input = w.document.getElementById("search-input");
  input.value = "t";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  assert.equal(w.document.querySelectorAll(".search-results li a").length, 0, "no results for 1 char");
});

test("a shard batch resolving AFTER close does not reopen the search panel", async () => {
  const name = pad3(bktOf.anonymity);
  const sh = {}; sh[name] = "h1";
  const manifest = { v: 1, buckets: FX.buckets, docs: 1, avgdl: 10, dl: [10], base: "search/ft/", sh };
  const w = load('<div class="site-search"><input type="checkbox" id="search-toggle">' +
    '<input id="search-input"></div>', { searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }], manifest });
  // Controllable fetch: manifest + index resolve now; the shard waits until we release it, so we
  // can close the panel WHILE the full-text batch is still in flight.
  let releaseShard;
  const shardGate = new Promise((r) => { releaseShard = r; });
  w.fetch = (u) => {
    u = String(u);
    if (/fulltext-manifest/.test(u)) return Promise.resolve({ ok: true, json: () => Promise.resolve(manifest) });
    if (/\/ft\/\d+\.json/.test(u)) return shardGate.then(() => ({ ok: true, json: () => Promise.resolve({ anonymity: [[0, 0, [5]]] }) }));
    if (/search-index/.test(u)) return Promise.resolve({ ok: true, json: () => Promise.resolve([{ t: "Firewall", u: "wiki/Firewall/" }]) });
    return Promise.resolve({ ok: false, json: () => Promise.resolve(undefined) });
  };
  const input = w.document.getElementById("search-input");
  input.value = "anonymity";                   // no title hit; the shard fetch is pending on the gate
  input.dispatchEvent(new w.Event("input"));
  await tick();
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  const results = w.document.querySelector(".search-results");
  assert.ok(results.hidden, "panel closed on Escape");
  releaseShard();                              // the body shard arrives LATE
  await tick(); await tick();
  assert.ok(results.hidden, "a late shard batch must NOT reopen the closed panel");
  assert.equal(results.querySelectorAll("li a").length, 0, "no stale body rows appended after close");
});

test("hovercards: a citation anchor with no href resolves to no footnote (href defaults to empty)", async () => {
  const w = load('<div class="wiki-content"><sup class="reference"><a>no href</a></sup>' +
    '<li id="fn1">note</li></div>');
  w.document.querySelector("sup.reference a").dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 240));
  assert.equal(w.document.querySelector(".hovercard-ref"), null, "an href-less citation anchor yields no card");
});

test("modal: closing tolerates an opener that cannot be focused (progressive-enhancement guard)", () => {
  const w = load('<button data-modal-open="m1">open</button>' +
    '<div id="m1" class="mini-modal" hidden><button class="mm-close">x</button></div>');
  const trigger = w.document.querySelector("[data-modal-open]");
  trigger.focus();   // so the modal records this trigger as the opener to refocus on close
  Object.defineProperty(trigger, "focus", { value: undefined, configurable: true });  // ...but it has no usable focus()
  trigger.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const m = w.document.getElementById("m1");
  assert.ok(m.classList.contains("active"), "modal opened");
  assert.doesNotThrow(() => w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true })),
    "close tolerates an opener lacking focus()");
  assert.ok(!m.classList.contains("active"), "modal closed cleanly");
});

test("modal: closing tolerates a null document.activeElement opener (no refocus, clean close)", () => {
  // A real browser can report document.activeElement === null (detached/blurred document); the
  // opener is read AT OPEN, so force it null to drive close()'s `opener && ...` left (falsy) arm.
  const w = load('<button data-modal-open="m1">open</button>' +
    '<div id="m1" class="mini-modal" hidden><button class="mm-close">x</button></div>');
  Object.defineProperty(Object.getPrototypeOf(w.document), "activeElement", { configurable: true, get: () => null });
  assert.equal(w.document.activeElement, null, "activeElement forced null (opener will be falsy)");
  const trigger = w.document.querySelector("[data-modal-open]");
  trigger.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const m = w.document.getElementById("m1");
  assert.ok(m.classList.contains("active"), "modal opened with a null opener");
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.ok(!m.classList.contains("active") && m.hidden, "modal closes cleanly with no opener to refocus");
});

test("modal: a throwing opener.focus() on close is swallowed (refocus try/catch)", () => {
  // opener is truthy AND has a focus() (if-true -> enter the try), but focus() throws -> the catch
  // clause runs. A pre-focused input is the recorded opener so the click default does not disturb it.
  const w = load('<input id="prefocus"><button data-modal-open="m1">open</button>' +
    '<div id="m1" class="mini-modal" hidden><button class="mm-close">x</button></div>');
  const pre = w.document.getElementById("prefocus");
  pre.focus();                                   // activeElement = pre -> recorded as the opener
  Object.defineProperty(pre, "focus", { configurable: true, value: () => { throw new Error("boom"); } });
  const trigger = w.document.querySelector("[data-modal-open]");
  trigger.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  const m = w.document.getElementById("m1");
  assert.ok(m.classList.contains("active"), "modal opened");
  assert.doesNotThrow(() => w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true })),
    "a throwing refocus is caught, not propagated");
  assert.ok(!m.classList.contains("active") && m.hidden, "modal closed despite the throwing refocus");
});

test("comparison-more: a .cmp-more-btn not inside a .cmp-more-ctrl row is left untouched", () => {
  // table ancestor present, ctrl row absent -> initComparisonMore's `!row` guard returns early.
  const w = load('<div class="wiki-content"><table class="comparison-table"><tbody>' +
    '<tr><td><button type="button" class="cmp-more-btn">Compare more</button></td></tr>' +
    '</tbody></table></div>');
  const table = w.document.querySelector(".comparison-table");
  const btn = w.document.querySelector(".cmp-more-btn");
  assert.ok(!table.classList.contains("cmp-collapsed"), "no ctrl row -> table not collapsed");
  assert.equal(btn.getAttribute("aria-expanded"), null, "no aria-expanded wired on the orphan button");
  btn.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  assert.ok(!table.classList.contains("cmp-collapsed"), "click is inert (no toggle handler bound)");
});

test("tab keyboard: a keydown bubbling from a NESTED tablist is ignored by the ancestor tablist", () => {
  // The roving-tabindex handler is scoped via closest('[role=tablist]') === ul; a key event whose
  // nearest tablist is a different (nested) one must not steal the ancestor's selection.
  const w = load(`
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section active"><div class="tcc-title"><h3 id="o1">O1</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="o2">O2</h3></div></div>
      </div>
    </div>`);
  const ctrl = w.document.querySelector(".tab-content-controller");
  const ul = ctrl.querySelector(".mininav > ul");
  const secs = ctrl.querySelectorAll(".tcc-content > .tcc-section");
  // Graft a nested tablist inside the first pill's <li>, then fire a key from inside it.
  const nested = w.document.createElement("div");
  nested.setAttribute("role", "tablist");
  const innerBtn = w.document.createElement("button");
  nested.appendChild(innerBtn);
  ul.querySelector("li").appendChild(nested);
  innerBtn.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.ok(secs[0].classList.contains("active") && !secs[1].classList.contains("active"),
    "ancestor tablist selection unchanged (nested-tablist key not stolen)");
});

test("tab keyboard: an arrow key is inert once the tablist has no .tcc-tab children", () => {
  // After the pills are removed, the live keydown read finds zero tabs -> `!tabs.length` return.
  const w = load(`
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section active"><div class="tcc-title"><h3 id="a">A</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="b">B</h3></div></div>
      </div>
    </div>`);
  const ctrl = w.document.querySelector(".tab-content-controller");
  const ul = ctrl.querySelector(".mininav > ul");
  const secs = ctrl.querySelectorAll(".tcc-content > .tcc-section");
  while (ul.firstChild) ul.removeChild(ul.firstChild);   // strip every pill
  ul.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.ok(secs[0].classList.contains("active") && !secs[1].classList.contains("active"),
    "no tabs -> handler bails, active section unchanged");
});

test("syncTabsFromHash tolerates a hash target whose enclosing .tcc-section has a null parent", () => {
  // documentElement carries class tcc-section + the hash id -> its parentElement is null, driving
  // the `p && p.closest ? ... : null` else arm. The chain's section has no controller, so a real
  // body tab controller must be left at its default.
  const w = load(`
    <div class="tab-content-controller">
      <div class="mininav"></div>
      <div class="tcc-content">
        <div class="tcc-section active"><div class="tcc-title"><h3 id="one">One</h3></div></div>
        <div class="tcc-section"><div class="tcc-title"><h3 id="two">Two</h3></div></div>
      </div>
    </div>`, { hash: "#rootsec", preEval: (win) => {
      win.document.documentElement.id = "rootsec";
      win.document.documentElement.classList.add("tcc-section");
    } });
  const secs = w.document.querySelectorAll(".tab-content-controller .tcc-content > .tcc-section");
  assert.ok(secs[0].classList.contains("active") && !secs[1].classList.contains("active"),
    "root-level pseudo-section hash activates nothing; body controller stays on its default tab");
});

test("tokenize returns [] for a punctuation-only string (no [a-z0-9] match)", () => {
  const S = load("<main>x</main>").mwSearch;
  assert.equal(JSON.stringify(S.tokenize("!!!")), "[]", "no word chars -> empty token list");
  assert.equal(JSON.stringify(S.tokenize("   ")), "[]", "whitespace-only -> empty token list");
});

test("scoreBM25 defaults docs/avgdl/dl when the manifest omits them", () => {
  // n||1, avgdl||1, dl||[] all fall back; dl[id]||avgdl supplies the missing doc length.
  const score = load("<main>x</main>").mwSearch.score;
  const r = score({}, ["a"], [[[0, 0, [1]]]]);
  assert.equal(r.length, 1, "the single candidate survives with a bare manifest");
  assert.equal(r[0][0], 0, "page 0 scored");
  // With n=1, df=1, tf=1, docLen=avgdl=1: score reduces exactly to idf = ln(4/3).
  assert.ok(Math.abs(r[0][1] - Math.log(4 / 3)) < 1e-9, "defaulted fields yield the ln(4/3) BM25 score");
});

test("scoreBM25 intersects by scanning the shorter posting list", () => {
  // list[1] (len 1) is shorter than list[0] (len 2) -> shortest updates to 1; only the page in
  // BOTH lists survives the AND.
  const score = load("<main>x</main>").mwSearch.score;
  const r = score({ docs: 2, avgdl: 4, dl: [4, 4] }, ["a", "b"],
    [[[0, 0, [1]], [1, 0, [1]]], [[1, 0, [1]]]]);
  assert.equal(JSON.stringify(r.map((x) => x[0])), "[1]",
    "page 1 (in both lists) kept; page 0 (only in the longer list) excluded");
});

test("scoreBM25 breaks an exact score tie by ascending pageId", () => {
  // Two identical postings -> equal scores -> the `y[1]-x[1] || x[0]-y[0]` tie-break orders by id.
  const score = load("<main>x</main>").mwSearch.score;
  const r = score({ docs: 2, avgdl: 10, dl: [10, 10] }, ["x"], [[[0, 0, [1]], [1, 0, [1]]]]);
  assert.equal(r[0][1], r[1][1], "the two pages score identically");
  assert.equal(JSON.stringify(r.map((x) => x[0])), "[0,1]", "tie broken deterministically by pageId asc");
});

test("full-text: a repeated query token is deduplicated (behaves as the single term)", async () => {
  const name = pad3(bktOf.tor);
  const shard = {}; shard[name] = { tor: [[0, 0, [3]], [1, 1, [0]]] };  // page0 body, page1 title+body
  const sh = {}; sh[name] = "deadbeef";
  const w = load('<input id="search-input">', {
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }, { t: "Tor", u: "wiki/Tor/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 2, avgdl: 20, dl: [30, 10], base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "tor tor";                  // no title holds "tor tor" -> title pass renders nothing
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const links = [...w.document.querySelectorAll(".search-results li a")].map((a) => a.textContent);
  assert.deepEqual(links, ["Tor", "Firewall"],
    "the duplicate 'tor' is dropped; results match the single-term 'tor' query");
});

test("search Enter falls back to the first rendered body row when no title matches", async () => {
  // bestMatch returns null (no title holds the query), but the full-text pass rendered body rows,
  // so Enter navigates to the first rendered row (the `if (firstLink)` true arm). Hash hrefs +
  // bundle appSrc (rootPrefix "") make the navigation observable.
  const name = pad3(bktOf.anonymity);
  const shard = {}; shard[name] = { anonymity: [[1, 0, [5]], [2, 0, [2]]] };
  const sh = {}; sh[name] = "abc12345";
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",
    searchIndex: [{ t: "Firewall", u: "#firewall" }, { t: "Tor", u: "#tor" },
                  { t: "Networking Guide", u: "#net" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 3, avgdl: 53.33, dl: [50, 10, 100],
                base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "anonymity";
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const first = w.document.querySelector(".search-results li a").getAttribute("href");
  assert.ok(first && first[0] === "#", "a body row is on screen with a hash href");
  input.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Enter" }));
  await tick();
  assert.equal(w.location.hash, first, "Enter with no title match navigates to the first body row");
});

test("hovercards: a reference anchor with empty text yields a bare 'Footnote' headline", async () => {
  // refList[idx].textContent is "" -> the `|| ""` empty arm -> number-less 'Footnote' title.
  const w = load('<div class="wiki-content"><sup class="reference"><a href="#fn1"></a></sup>' +
    '<li id="fn1">The note body.</li></div>');
  w.document.querySelector("sup.reference a").dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 260));
  const card = w.document.querySelector(".hovercard");
  assert.ok(card && !card.hidden, "card shown for the empty-label citation");
  assert.ok(/The note body/.test(card.textContent), "footnote body carried over");
  assert.equal(card.querySelector(".hovercard-title").textContent.trim(), "Footnote",
    "empty citation label -> bare 'Footnote' headline (no number)");
});

test("hovercards: arrow keys are inert while a PAGE-preview card is shown (curRef stays -1)", async () => {
  const w = load('<div class="wiki-content"><p><a href="Firewall/">Firewall</a></p></div>',
    { appSrc: "../app.min.js", previews: { "wiki/Firewall/": { t: "Firewall", d: "Blocks traffic." } } });
  w.document.querySelector(".wiki-content a").dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  await tick();
  await new Promise((r) => setTimeout(r, 260));
  assert.ok(w.document.querySelector(".hovercard .hovercard-page"), "page-preview card shown");
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.ok(w.document.querySelector(".hovercard .hovercard-page"), "card unchanged (curRef<0 -> arrow ignored)");
  assert.equal(w.document.querySelectorAll(".hovercard-ref").length, 0, "no footnote card rendered by the arrow");
});

test("share tooltip: a document click outside any .headline-anchor opens no menu (onToggle a-guard)", () => {
  // onToggle's target has no .headline-anchor ancestor -> a is null -> `a && a.closest` short-
  // circuits (no tip) -> early return, nothing toggled.
  const w = load('<div class="wiki-content"><h2><span class="share-tooltip">' +
    '<a class="headline-anchor" href="#s">#</a></span> Heading</h2>' +
    '<p id="plain">body text</p></div>');
  w.document.getElementById("plain").dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true }));
  assert.equal(w.document.querySelectorAll(".share-tooltip.share-open").length, 0,
    "a click with no .headline-anchor ancestor opens no share menu");
});

test("share tooltip: a click whose target is the document node is tolerated (e.target.closest guard)", () => {
  // Dispatching on the document itself gives e.target === document, which has no .closest ->
  // `e.target && e.target.closest` is falsy -> the ternary's else (a = null) runs, nothing opens.
  const w = load('<div class="wiki-content"><h2><span class="share-tooltip">' +
    '<a class="headline-anchor" href="#s">#</a></span> Heading</h2></div>');
  assert.doesNotThrow(() => w.document.dispatchEvent(new w.MouseEvent("click", { bubbles: true })),
    "a document-targeted click does not throw");
  assert.equal(w.document.querySelectorAll(".share-tooltip.share-open").length, 0,
    "no share menu toggled for a target that lacks .closest");
});

test("full-text: a stopword-only query tokenizes to nothing and appends no body rows", async () => {
  // tokenize('the www') -> [] (both are stopwords), so fullText's `if (!terms.length) return`
  // fires -- no shard is fetched and no body row is appended.
  const name = pad3(bktOf.tor);
  const shard = {}; shard[name] = { tor: [[0, 0, [3]]] };
  const sh = {}; sh[name] = "feed0001";
  const w = load('<input id="search-input">', {
    searchIndex: [{ t: "Firewall", u: "wiki/Firewall/" }, { t: "Tor", u: "wiki/Tor/" }],
    manifest: { v: 1, buckets: FX.buckets, docs: 2, avgdl: 20, dl: [30, 10], base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "the www";                  // 2+ chars, no colon -> reaches fullText; all stopwords
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const results = w.document.querySelector(".search-results");
  assert.equal(results.querySelectorAll("li a").length, 0, "no title and no body rows for a stopword-only query");
  assert.ok(results.hidden, "results panel stays hidden");
});

test("hovercards: a page link whose href is cleared mid-fetch yields no card (href || \"\" guard)", async () => {
  // onEnter's sync guard sees the href, schedules the previews fetch; the attribute is removed
  // before it resolves, so pageNodes reads a null href -> `|| ""` -> empty -> new URL("") throws
  // -> caught -> no card.
  const w = load('<div class="wiki-content"><p><a href="Firewall/">Firewall</a></p></div>',
    { appSrc: "../app.min.js", previews: { "wiki/Firewall/": { t: "Firewall", d: "Blocks traffic." } } });
  const a = w.document.querySelector(".wiki-content a");
  a.dispatchEvent(new w.MouseEvent("mouseover", { bubbles: true }));
  a.removeAttribute("href");                 // cleared after the guard, before the fetch resolves
  await tick();
  await new Promise((r) => setTimeout(r, 260));
  assert.equal(w.document.querySelector(".hovercard .hovercard-page"), null,
    "an anchor that lost its href resolves to no preview card");
});

// ---- navSafe URL-safety guard: tampered same-origin index/attribute targets are DROPPED --------
// navSafe(h, allowAbsolute) is the defense-in-depth guard beneath CSP+TT. A tampered index entry
// or href (non-string, protocol-relative //host, or a javascript:/data: scheme) must never be
// rendered as a search row or auto-driven by the download-modal nav sink. Each test asserts the
// real DROP (no <li>, count unchanged, no modal/nav) and fails if the guard were removed.

test("navSafe rejects a non-string target (tampered index entry whose u is not a string)", () => {
  const navSafe = load("<main>x</main>").mwSearch.navSafe;
  assert.equal(navSafe(123, false), false, "a number is not a safe target");
  assert.equal(navSafe(null, false), false, "null is not a safe target");
  assert.equal(navSafe(undefined, true), false, "undefined is not safe even with allowAbsolute");
  assert.equal(navSafe({}, true), false, "a non-string object is not a safe target");
  // control: a plain relative string IS safe, proving the above falses come from the type guard,
  // not a blanket reject (and that removing the guard would throw on .replace, failing this test).
  assert.equal(navSafe("wiki/Firewall/", false), true, "a plain relative string is same-origin safe");
});

test("navSafe rejects a protocol-relative //host target (cross-origin)", () => {
  const navSafe = load("<main>x</main>").mwSearch.navSafe;
  assert.equal(navSafe("//evil.com/x", false), false, "//host is cross-origin, dropped");
  assert.equal(navSafe("//evil.com/x", true), false,
    "//host stays dropped even with allowAbsolute (it is not an explicit http(s) scheme)");
  // control: the same host behind an explicit https scheme IS allowed under allowAbsolute, proving
  // the falses above are the // guard specifically, not the absolute-target path.
  assert.equal(navSafe("https://evil.com/x", true), true, "explicit https absolute is permitted when allowAbsolute");
});

test("search drops a title hit whose target fails navSafe (tampered javascript: u -> no row)", async () => {
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",   // rootPrefix "" -> href is e.u verbatim (no relative prefix to neutralise the scheme)
    searchIndex: [{ t: "Firewall", u: "javascript:alert(1)" }],
  });
  const input = w.document.getElementById("search-input");
  input.value = "firewall";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  const results = w.document.querySelector(".search-results");
  assert.equal(results.querySelectorAll("li").length, 0, "the tampered javascript: target is dropped: no <li> appended");
  assert.ok(results.hidden, "with the only hit dropped, the results panel stays hidden");
});

test("search renders safe title hits but drops the tampered //host one (count = real rows only)", async () => {
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",
    searchIndex: [{ t: "Firewall Guide", u: "wiki/Firewall_Guide/" },
                  { t: "Firewall Evil", u: "//evil.com/phish" }],
  });
  const input = w.document.getElementById("search-input");
  input.value = "firewall";
  input.dispatchEvent(new w.Event("input"));
  await tick();
  const links = [...w.document.querySelectorAll(".search-results li a")].map((a) => a.textContent);
  assert.equal(JSON.stringify(links), JSON.stringify(["Firewall Guide"]),
    "only the same-origin hit renders; the //evil.com title hit is dropped, not counted");
});

test("full-text drops a body-only match whose target fails navSafe (tampered //host u -> no append)", async () => {
  const name = pad3(bktOf.anonymity);
  const shard = {}; shard[name] = { anonymity: [[0, 0, [2]]] };   // page 0 is a body hit for 'anonymity'
  const sh = {}; sh[name] = "abc12345";
  const w = load('<input id="search-input">', {
    appSrc: "../../vendor-bundle.js",   // rootPrefix "" -> href is e.u verbatim, so //evil.com fails navSafe
    searchIndex: [{ t: "Networking Guide", u: "//evil.com/phish" }],   // title lacks 'anonymity' -> title pass is empty
    manifest: { v: 1, buckets: FX.buckets, docs: 1, avgdl: 10, dl: [10], base: "search/ft/", sh },
    shards: shard,
  });
  const input = w.document.getElementById("search-input");
  input.value = "anonymity";
  input.dispatchEvent(new w.Event("input"));
  await tick(); await tick();
  const results = w.document.querySelector(".search-results");
  assert.equal(results.querySelectorAll("li a").length, 0,
    "the BM25-ranked body hit has a tampered target -> appendResult drops it, no row added");
  assert.ok(results.hidden, "no row added -> the results panel stays hidden");
});

test("download modal: a tampered javascript: href is not navigated (nav sink dropped, no modal)", () => {
  const w = load('<a class="download-button-v2 dlbtn-modal" href="javascript:alert(1)">Get</a>');
  const link = w.document.querySelector("a.dlbtn-modal");
  const ev = new w.MouseEvent("click", { bubbles: true, cancelable: true });
  link.dispatchEvent(ev);
  assert.equal(w.document.getElementById("download-button-modal"), null,
    "navSafe(href,true) false -> handler returns before building/driving the modal");
  assert.equal(ev.defaultPrevented, false,
    "the click is NOT intercepted (no preventDefault), so app.js never auto-drives the javascript: target");
});
