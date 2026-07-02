# git-meld review-evasion threat model

`git-meld` is a code-REVIEW tool (a git external diff driver). Its overriding
invariant: **a real change must never be rendered as empty or misleading output**
-- a change the reviewer cannot see is a change an attacker can hide.

This file maps the known ways to hide a change from a diff/review tool to the
`git-meld` defense and the test that guards it. Sources: Trojan Source (Boucher &
Anderson, USENIX Security 2023; CVE-2021-42574 Bidi, CVE-2021-42694 homoglyph);
git `gitattributes(5)`; git submodule CR abuse (CVE-2025-48384); plus an
AI-reviewer brainstorm (Codex + a fresh-context Claude subagent) and a
fan-out deep-research pass. Two test suites exercise these:
`git-meld-tests` (adversarial) and `git-meld-tests-fuzz` (randomised).

## Where git DOES invoke the driver (git-meld can self-defend)

| Technique | Mechanism | git-meld defense | Test |
|---|---|---|---|
| Mode-only change (+x) | A data file / script made executable with no content change; a content diff shows nothing | `MODE CHANGE` banner from the mode args; `EXECUTABLE (+x)` note | `mode-only-+x` |
| Symlink swap (mode 120000) | File replaced by / retargeted to a symlink (e.g. -> /etc/shadow); blob content is the target, which meld shows as innocuous text | `SYMLINK old -> new` printed explicitly; do not hand a link to meld as a file | `file->symlink swap`, fuzz |
| Gitlink content spoof | A REGULAR file whose content is `Subproject commit <hex>` routes through the (meld-less) submodule branch, hiding the file body | Decide the submodule branch by MODE (160000), not content; warn on the mimic | `fake-Subproject content spoof` |
| Submodule path confusion (CVE-2025-48384-ish) | Odd / symlinked submodule path redirects the inner diff | `git -C <path>` (not `cd`) + a repo check; never `cd` into an attacker-influenced path | submodule suite |
| Unfetched submodule commits | Inner `git diff old new` fails when commits are absent | Print the gitlink transition, then fail LOUD (never `\|\| true`) | `run-adversarial` (0/4 hidden) |
| Trojan Source (CVE-2021-42574 / -42694) | Bidi overrides / invisible / zero-width Unicode in comments & strings reorder or hide logic | Scan the new blob for Bidi (U+202A-E, U+2066-9), ZWSP, BOM, and C0 controls; warn before opening meld | `trojan-source bidi unicode`, fuzz |
| Malformed driver args | Crafted modes / hashes | Mode-format sanity warning | (arg validation) |

## Where git does NOT invoke the driver (needs the re-dispatch pre-flight)

git skips the external diff entirely for these, so a per-file driver is blind.
The `git meld` re-dispatch prints a `git diff --no-ext-diff --stat --summary
--find-renames` PRE-FLIGHT first, so every changed path still appears, and warns
loudly when `.gitattributes` itself changes.

| Technique | Mechanism | Coverage |
|---|---|---|
| `.gitattributes` `binary` / `-diff` | git emits only "Binary files differ"; driver skipped | Pre-flight lists the path; `.gitattributes`-changed warning. Test: `driver-skipped (binary) file listed in pre-flight` |
| `.gitattributes` `diff=<driver>` / textconv | Diff routed through an arbitrary lossy transform | Pre-flight uses `--no-ext-diff` (raw) |
| NUL-byte auto-binary | A NUL in the first ~8000 bytes auto-classifies binary; driver skipped | Pre-flight `--stat`/`--numstat` still lists it; fuzz emits NUL blobs |
| Git-LFS pointer (`diff=lfs`) | Pointer shown, not content | Pre-flight lists the path |

## Known residual gaps (documented, not fully closed by the driver)

- **Homoglyph identifiers** (CVE-2021-42694): mixed-script lookalikes are not yet
  flagged (only Bidi/invisible/control are). A mixed-script identifier scan is a
  future addition.
- **Review-PLATFORM collapsing** (GitHub `linguist-generated`, large/collapsed
  diffs): out of scope for a local diff driver; review locally with `git meld`.
- **Pathspec exclusions / evil-merge combined diffs**: a reviewer who scopes the
  diff can still miss files; the pre-flight covers the whole given range but not
  paths the reviewer excludes.
