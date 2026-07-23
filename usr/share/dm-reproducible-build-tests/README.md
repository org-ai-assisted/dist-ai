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

## Follow-up: comparator unification (open)

Two comparators diverge in the tree:

- `dm-reproducible-compare-artifacts` (developer-meta-files) -- sha256 verdict +
  diffoscope-to-explain, best input hygiene. This runner uses it.
- `ci/reproducible-compare-artifacts` -> `help-steps/reproducible-compare` --
  diffoscope-verdict + an expected-to-differ **allowlist**; the pair the current
  `local-reproducible.yml` CI lane invokes.

The sha256 verdict is the rigorous, cheap, format-independent truth, but reports
FAIL while images are not yet bit-reproducible, where the allowlist compare
reports PASS. The clean end state is ONE canonical comparator (sha256) that gains
an optional `--allowlist` folding in the expected-to-differ set, then this runner
gains an `--allowlist` passthrough. Until that lands, a real run here is honestly
RED (matching `local-reproducible.yml`'s "expected red" status).
