# lockfile-tests

Comprehensive test + fuzz for the shared `flock` lock helper and its per-key
wrapper.

## Subjects

- **`lockfile.sh`** (`helper-scripts`, `usr/libexec/helper-scripts/lockfile.sh`)
  -- the atomic `flock` `FLOCKER`-re-exec mutex a script *sources* to self-lock,
  plus the optional `LOCK_NAME` env override that locks per key instead of by
  the script's own path.
- **`locked-run`** (`dist-encrypted`, `usr/local/bin/locked-run`) -- runs an
  arbitrary command (bash or python) under a per-key `lockfile` lock; used by
  the onion `*/5` cron jobs so a slow run for one instance does not pile up or
  skip the others.

## What it proves

`lockfile.sh`: a second instance of the same sourcing script skips while the
first holds the lock and re-acquires after release; `LOCK_NAME` locks per key
(same key skips, distinct keys run concurrently); an unset `LOCK_NAME` is
backward-compatible (self-lock by `realpath`); a held-lock skip exits non-zero;
a path-like key is handled.

`locked-run`: per-key skip + concurrency; exit-code propagation; the wrapped
command inherits neither `LOCK_NAME` nor `FLOCKER`; a wrapped command that itself
sources `lockfile` does not self-deadlock; the usage guards.

A fuzz phase hammers random keys and asserts per-key isolation against a trivial
key-equality oracle.

## Run

```
lockfile-tests [--iterations N] [--seed N] [--fuzz-only]
```

No root, no network. Subjects default to the installed paths; set
`LOCKFILE_SH_REPO` to a `helper-scripts` checkout and/or `LOCKED_RUN_REPO` to a
`dist-encrypted` checkout to test those. An absent subject (or a `locked-run`
whose `/usr/local/bin/lockfile` is not the `flock` version it sources) is
skipped with a reason, never a false failure.
