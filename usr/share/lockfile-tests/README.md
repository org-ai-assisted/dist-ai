# lockfile-tests

Comprehensive test + fuzz for the shared `flock` lock helper, in both of its
modes.

## Subject

**`lockfile.sh`** (`helper-scripts`, `usr/libexec/helper-scripts/lockfile.sh`)
-- the atomic `flock` `FLOCKER`-re-exec mutex, used two ways:

- **SOURCE mode** -- a script `source`s it to self-lock: only one instance runs
  at a time, keyed by the script's own path, or by the optional `LOCK_NAME` env
  override to lock per key instead.
- **WRAP mode** -- executed as `lockfile.sh <lock-key> -- <command> [args...]`
  to run any command (bash or python) under a per-key lock; used by the onion
  `*/5` cron jobs so a slow run for one instance does not pile up or skip the
  others. (This retired the old `dist-encrypted` `locked-run` wrapper.)

## What it proves

SOURCE mode: a second instance of the same sourcing script skips while the first
holds the lock and re-acquires after release; `LOCK_NAME` locks per key (same
key skips, distinct keys run concurrently); an unset `LOCK_NAME` self-locks by
`realpath`; a held-lock skip exits non-zero; a path-like key is handled.

WRAP mode: per-key skip + concurrency; exit-code propagation; the wrapped
command inherits neither `LOCK_NAME` nor `FLOCKER`; a wrapped command that itself
sources `lockfile` does not self-deadlock; the usage guards.

A fuzz phase hammers random keys through wrap mode and asserts per-key isolation
against a trivial key-equality oracle.

## Run

```
lockfile-tests [--iterations N] [--seed N] [--fuzz-only]
```

No root, no network. The subject defaults to the installed
`/usr/libexec/helper-scripts/lockfile.sh`; set `LOCKFILE_SH` to an explicit file
or `LOCKFILE_SH_REPO` to a `helper-scripts` checkout to test that instead. There
are no skip paths: a missing or non-executable `lockfile.sh`, or one lacking a
tested feature, FAILS.
