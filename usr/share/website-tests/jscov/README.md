# jscov -- first-party JS unit-coverage lane (100% gate)

A standalone/CI lane that unit-tests the sites' first-party JavaScript under jsdom and gates
**100%** statements/branches/functions/lines (c8), confined in the review sandbox.

## Run

    webcheck-jscov-sandbox <site-root> [<site-root> ...]

The driver stages `jscov/` + each site's `*.js` (as `roots/<site>/<rel>`), syncs into the
sandbox, and runs `run.sh` (c8 `--check-coverage ... 100` over `covered.txt`, `node --test jscov/`).
Needs `provision jstest` (node + jsdom + c8) in the sandbox.

## Mechanism (how a browser IIFE reaches 100%)

`harness.js` `loadScript(jsPath, bodyHtml, opts)` builds a fresh jsdom window, installs stubs
(`prompt`/`window.open`/`navigator.clipboard`, synchronous `setTimeout`), and runs the script via
`vm.Script(src, {filename: jsPath})` in the window's VM context -- the real filename makes c8
attribute coverage to the source file. A test prepares the DOM, then exercises every branch.
See `share.test.js` for the worked pattern.

## Covered set (EXPLICIT + GROWING -- not a silent subset)

`covered.txt` lists exactly the files the gate requires at 100%. A file not listed is NOT
silently green -- it is simply not yet gated. To add one: write `<name>.test.js` (jsdom via
`harness.js`, 100% of its branches), add its `roots/<site>/<rel>` path to `covered.txt`, re-run.

### Covered now (all 15 FAMILY first-party JS files, gated at 100%)
- family `share.js` (3 byte-identical copies) -- `share.test.js`.
- secure-terminal: `share.js` (host-regex variant), `copy.js`, `chat-view/mockup.js`,
  `attacks/pastejack.js`, `hero.js` -- `st-share`/`st-copy`/`mockup`/`pastejack`/`hero.test.js`.
- output-lies: `git-diffs-lie/copy.js`, `git-diffs-lie/all/copy.js`, `paste/copy.js`,
  `analyze/{analyzer,sandbox,ui}.js`, `terminal/{playback,xray}.js`, `quiz/quiz.js` --
  `ol-copy`/`analyzer`/`sandbox`/`ui`/`playback`/`xray`/`quiz.test.js`. OL-dependent lanes
  (xray/sandbox/ui) get the real analyzer injected via `require()`.

### Wiki stage JS -- tested, gating DEFERRED to mw-static-generator Phase 4
`app.test.js` (177 cases, every feature + branch) and `generated.test.js` cover the wiki stage
`app.js` / `search-index.js` / `page-previews.js`. They self-skip unless a wiki stage root is
passed, and are NOT in `covered.txt`, because:
- `app.js` has 5 genuinely-dead defensive branches jsdom cannot reach (a focus-trap helper
  re-checks an `active` the caller already guarantees; a `p && p.closest` guard for a never-null
  parent; a `new URL` catch valid input never throws; two redundant guards). Reaching 100%
  needs a source-side `/* c8 ignore */`, which belongs with the app.js SOURCE in
  mw-static-generator.
- the stage tree lives in `~/private-sources/<site>-wiki-static`, not in dist-ai CI.
Phase 4 (mw-static depends on the core) is the home for wiki-JS 100% gating: there the source,
its c8-ignores, the stage root and its CI are together. To activate then: pass a stage root, add
the three `roots/kicksecure-stage.github.io/*.js` paths to `covered.txt`.

A file not listed in `covered.txt` is NOT silently green -- it is simply not yet gated.
