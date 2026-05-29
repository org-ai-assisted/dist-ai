# dist-ai

AI-committed regression-testing tooling for the Kicksecure / Whonix
ecosystem. Designed for content that is too high-volume for human
review: large baseline corpora, fuzz-test inputs, generated fixtures.

## Components

| Component | Status | Location |
|---|---|---|
| `mediawiki-dom-snapshot` | shipping | `usr/share/mediawiki-dom-snapshot/` |
| `discourse-dom-snapshot` | planned  | `usr/share/discourse-dom-snapshot/` |
| `sdwdate-ci-fuzz`        | planned  | `usr/share/sdwdate-ci-fuzz/` |

Each component is independent. Each ships its own Debian binary
package via `debian/<component>.install`. The repo follows the FHS
layout used by the rest of the Kicksecure packaging tree.

## mediawiki-dom-snapshot

Drives headless Chromium via Playwright against a running MediaWiki,
captures the post-JS DOM for a configured set of pages, and normalises
the output so byte-level diffs surface only meaningful changes (CSP
nonces, ResourceLoader version hashes, parser-cache timestamps and
other per-request flake are scrubbed).

Use case: detect HTML/CSS regressions introduced by MediaWiki core or
extension upgrades, or by site-CSS refactors. Capture a baseline
before the change, run again after, diff.

### Usage

```
# capture + normalise against the live wiki
mediawiki-dom-snapshot

# diff a captured fixture set against the shipped baseline
mediawiki-dom-snapshot diff baseline <tag>

# promote a captured fixture set to be the new baseline
mediawiki-dom-snapshot baseline-promote <tag>
```

Environment overrides:

| Var | Default | Meaning |
|---|---|---|
| `BASE_URL`     | `https://www.kicksecure.com` | target wiki origin |
| `PAGES_FILE`   | `/etc/mediawiki-dom-snapshot/pages.conf` | one title per line |
| `VIEWPORT`     | `1280x800` | browser viewport |
| `TIMEOUT_MS`   | `30000` | per-page timeout |
| `RAW_DIR`      | `/var/lib/mediawiki-dom-snapshot/raw` | raw HTML output |
| `FIX_DIR`      | `/var/lib/mediawiki-dom-snapshot/fixtures` | normalised output |
