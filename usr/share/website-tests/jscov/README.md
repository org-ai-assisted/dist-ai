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

### Covered now
- `share.js` (family; 3 byte-identical copies) -- `share.test.js`.

### Remaining first-party JS to cover (then add to covered.txt)
- `secure-terminal.github.io/share.js` (a variant of the family share.js)
- `copy.js` x4 distinct (secure-terminal; output-lies paste, git-diffs-lie, git-diffs-lie/all)
- `secure-terminal.github.io/hero.js`, `chat-view/mockup.js`, `attacks/pastejack.js`
- `output-lies.github.io/quiz/quiz.js`, `terminal/playback.js`, `terminal/xray.js`
- `output-lies.github.io/analyze/{analyzer,sandbox,ui}.js`
- wiki stage `app.js` (~1114 lines -- the large one), `search-index.js`, `page-previews.js`

Until every distinct first-party file is listed, this lane gates the listed subset at 100%; the
full "all JS at 100%" goal is reached when the Remaining list is empty.
