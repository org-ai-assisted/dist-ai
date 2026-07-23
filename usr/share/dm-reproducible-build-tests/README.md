# dm-reproducible-build-tests

A reproducibility test entry point in the dist-ai contract (0 PASS / 77 SKIP /
else FAIL). It does NOT re-implement the comparison; it delegates to the
canonical derivative-maker tools (resolved from a checkout, so they stay shipped
dev tools rather than being duplicated here):

- **compare-only** (`--dir-a DIR --dir-b DIR --target <iso|virtualbox|qcow2>`):
  compare two already-built output dirs via developer-meta-files
  `dm-reproducible-compare-artifacts` (whole-file sha256 verdict; diffoscope
  explains a mismatch).
- **build-twice** (`--target ... --arch <amd64|arm64> [--flavor F] [--freshness frozen]`):
  build the target twice and compare, via `ci/reproducible-build-twice`. Needs a
  full build host (docker + disk); SKIPs where that is absent.

The derivative-maker checkout is found via `--repo-root`, else
`$DERIVATIVE_MAKER_DIR`, else `~/derivative-maker`. It SKIPs (77) when no checkout
is found, neither mode's required args are given, or a required tool/dep
(diffoscope, the build host) is absent -- "cannot run a reproducibility test
here", not a failure. Like the other build-host suites it is deliberately NOT
registered in any `dist-ai-tests-all` array; it runs standalone / from the
dedicated reproducibility lane.

## Comparator allowlist

`dm-reproducible-compare-artifacts` (the sha256 comparator this runner uses) now
takes an optional `--allowlist FILE` of expected-to-differ diffoscope `--exclude`
globs; a sha256 mismatch confined to those paths is downgraded to PASS
(reproducible modulo the allowlist). Pass `--allowlist FILE` to this runner in
compare-only mode to use it. Omit it for the strict sha256 verdict -- honestly RED
until images are bit-reproducible. This makes the one sha256 comparator a superset
of the older allowlist-diffoscope path, so there is a single canonical comparator.
