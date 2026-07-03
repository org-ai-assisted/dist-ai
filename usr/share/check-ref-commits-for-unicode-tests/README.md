# check-ref-commits-for-unicode tests

Comprehensive test + fuzz for **check-ref-commits-for-unicode** -- the
helper-scripts git-ref guard that scans every commit a ref introduces
(`git log HEAD..<ref>`) for suspicious Unicode and fails if any is found.

For each new commit it runs

```
git show --no-ext-diff --unified=0 --no-textconv \
    --format='Author: %an\nAuthor email: %ae\nCommitter: %cn\n\
              Committer email: %ce\n%B' <commit>
```

and pipes the result through `unicode-show`. So it scans, per commit, not just
the **diff** but the commit **message** and the **author / committer name and
email** -- the places a Trojan-Source style attack can hide that a plain content
scan misses.

## Contract

- exit `0`: every new commit is clean; logs `No unicode detected.`
- exit `1`: **either** suspicious Unicode was found (a per-commit
  `Potentially malicious unicode detected in commit '<sha>'` warning, with
  `unicode-show`'s report) **or** a usage / setup error (no ref given, ref does
  not exist, cwd is not a git work tree, or no new commits in the ref). Exit `1`
  is overloaded; the suite distinguishes detection from error by the message.

The design choices are pinned by the tests: `--unified=0` avoids false positives
from unmodified empty context lines (which `unicode-show` flags as trailing
whitespace); `--no-ext-diff` / `--no-textconv` stop an external diff driver or a
textconv filter from hiding or altering the bytes; and the `--format` line pulls
the identity fields into the scan.

## Checks

- **[D] detection by location**: a hostile codepoint hidden in the file content,
  the commit message, the author name, the author email, the committer name, or
  the committer email each makes the tool exit `1` and name the offending commit.
  Plus a few different suspicious characters in content.
- **[S] self-safety**: even while reporting a commit stuffed with hostile
  Unicode, the tool's combined stdout+stderr stays pure ASCII (`unicode-show`
  renders the finding as `[U+XXXX]`; nothing raw reaches the terminal).
- **[B] benign**: a ref whose new commits are clean (including blank lines and a
  clean merge commit) exits `0`, so [D] is non-vacuous.
- **[M] multi-commit**: given clean + dirty + clean new commits, the tool flags
  the dirty one (by sha) and logs the clean ones as clean.
- **[E] errors**: no ref argument, a nonexistent ref, a ref with no new commits,
  and a cwd that is not a git work tree -- each exit `1` with its own message.
- **[F] fuzz**: random commits whose payload is either clean ASCII or carries a
  suspicious character in a random location, checked against an independent
  oracle -- exit `1` iff something suspicious was injected, else `0`, and the
  output always pure ASCII.

No root, no network. git is run hermetically (global/system config neutralised).
The test source is ASCII-only: suspicious characters are Python escapes, encoded
to real UTF-8 at runtime.

## Running

```
check-ref-commits-for-unicode-tests                  # corpus + semantics + fuzz
check-ref-commits-for-unicode-tests --iterations 200 --seed 7
check-ref-commits-for-unicode-tests-fuzz             # heavy fuzz sweep

# test a checkout instead of the installed tool
CHECK_REF_COMMITS_REPO=/path/to/helper-scripts check-ref-commits-for-unicode-tests
```

Each iteration builds a real git commit, so this suite is heavier per iteration
than the byte-level sibling suites; the default iteration count is lower.

The tool is resolved from `CHECK_REF_COMMITS_REPO` (a helper-scripts checkout,
whose `usr/bin` is put on `PATH` so its `unicode-show` is used and
`HELPER_SCRIPTS_PATH` points at it so it sources the checkout's
`log_run_die.sh`) else the installed `/usr/bin/check-ref-commits-for-unicode`.
