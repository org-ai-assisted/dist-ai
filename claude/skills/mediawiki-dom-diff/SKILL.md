---
name: mediawiki-dom-diff
description: "Prove a MediaWiki change (extension swap, template/widget refactor, migration) is render-equivalent -- that readers see the same thing -- with the dist-ai mediawiki-dom-snapshot tool. Use when verifying a refactor/migration changed nothing observable. Enforces: faithful before/after, a SAMPLE diff before the full run, normalize cosmetic noise, and investigate every real delta."
license: MIT
---

# mediawiki-dom-diff: prove a MediaWiki change is render-equivalent

## When to use

- You changed a MediaWiki (extension swap like Extension:Widgets -> PHP parser functions, template/skin/CSS refactor, content migration) and need to prove the **rendered output didn't change** -- what readers see is identical.
- The tool captures a per-page corpus (post-JS DOM, screenshot, asset bodies) for a BEFORE and an AFTER state and three-axis-diffs them (HTML text, asset content, screenshot pixels + perceptual hash).

## The tool

- `~/private-sources/dist-ai/usr/share/mediawiki-dom-snapshot/{snapshot,normalize,diff}.py`.
- Drive it with the **playwright venv** `/home/user/.venvs/playwright/bin/python`.
  - `usr/bin/mediawiki-dom-snapshot` wrapper hardcodes `/usr/share/...` and only works installed; from a source checkout call the scripts directly -- see the `playwright-install` skill for venv wiring.
- Capture: `snapshot.py` (-> `RAW_DIR`) then `normalize.py` (-> `FIX_DIR`). Env: `BASE_URL`, `PAGES_FILE` (one title/line), `RAW_DIR`, `FIX_DIR`, `CONCURRENCY` (default 4; 8 is fine), `TIMEOUT_MS`.
- Diff two normalized sets: `diff.py <fix-a> <fix-b> [--brief]`. Exit 0 = nothing observably changed; exit 1 = at least one real diff. `--brief` = per-page summary + a footer `N identical, N subpixel-only, N with-real-diffs`.
- **pHash distance is the strongest single signal**: `phash_dist=0` (or no pixel tag at all) = visually identical despite any source churn; `>=3` = real layout/colour shift.

## The order of operations -- do these, in this order

1. **Build a FAITHFUL before/after -- and prove it's faithful.**
   - **Same-wiki before/after is the cleanest**: roll ONE disposable wiki between states *in place* and capture each. Same hostname/DB/revid both times => zero environment noise by construction.
   - Cross-wiki (two different wikis) drags in hostname/DB/revid deltas on every page; only do it if you also extend the normalizer to scrub those.
   - **Verify the BEFORE state is genuine, not a broken hybrid.** A wiki can hold *migrated* content with the *old backend inactive* -> it dumps `{{#...}}` as raw literal text. That is NOT a faithful pre-migration render.
   - PROVE the old backend is really rendering (e.g. for Extension:Widgets: Smarty `compiled_templates` appear and pages show `widget-` classes with zero literal `{{#...}}`).

2. **SAMPLE FIRST -- always, never skip.**
   - Run a ~25-40 page sample diff *before* the full corpus.
   - Full run is long (e.g. ~1069 pages x 2 ~ 30 min); a sample catches a broken setup, a noisy normalizer, or an unexpected delta in ~5 min -- instead of producing 30 minutes of garbage you then redo.
   - Pick pages that exercise the change (the ones using the refactored widgets/templates) plus a few plain ones for a baseline.

3. **NORMALIZE what is sensibly cosmetic -- to avoid noise.**
   - Extend `normalize.py` so the diff surfaces REAL changes, not formatting churn.
   - Sensible to normalize: HTML whitespace (collapse text-node + comment whitespace, drop empty `<p></p>`), volatile fields (RequestId, nonces, build/version stamps, unix timestamps), and -- for cross-wiki only -- hostname / DB name / revision IDs.
   - Preserve whitespace inside `<pre>`/`<code>`/`<textarea>`/`<script>`/`<style>`.
   - **Never normalize away a real change** -- only cosmetic equivalence.
   - Known noise: the Smarty (Extension:Widgets) vs PHP-parser-function backends emit the same DOM with different whitespace + empty `<p>` -- pure cosmetics.

4. **INVESTIGATE every mystery -- that is the point of the diff.**
   - Each surviving real delta (asset / computed-style / DOM / pixel) gets *explained*: diff the actual bodies, decide expected-migration-change vs regression.
   - Do NOT shrug off or silently normalize an unexplained delta -- chasing it down is the entire value of the exercise.

## Endpoint resolution (dist-encrypted reproduction)

- The reproduction container serves `www.kicksecure.com` (default wiki) and `target.kicksecure.com` (target wiki), both pinned to the container `172.17.0.2` in the host `/etc/hosts` -- so `BASE_URL=https://www.kicksecure.com` hits the CONTAINER, not prod.
- To hit PROD instead, resolve the real IP via DoH and use `curl --resolve` / chromium `--host-resolver-rules`.
- The MWCD **lockdown** gates anonymous *special pages* and makes the anon API report description-less `File:` pages as `missing`, but anon *article/page web read works* -- verify via the canonical rendered page, never `Special:Redirect` (it's login-walled). See [[repro-wiki-image-verification]].

## Gotchas

- A shallow pre/post marker (e.g. `Widget:`-page count) can be wrong -- a wiki can be a broken hybrid. Verify the actual RENDER, not a DB count.
- Cross-wiki PRE-vs-POST can be meaningless: PRE may hold migrated content + an inactive backend (raw markup) plus hostname/DB/revid noise. Same-wiki + faithful backend avoids it.
