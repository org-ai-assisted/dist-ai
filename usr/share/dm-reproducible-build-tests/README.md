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

## Why no allowlist flag here (open: branch reconciliation)

The sha256 verdict is rigorous but reports RED while images are not yet
bit-reproducible, where the CI lane's allowlist-aware compare reports PASS. An
allowlist CANNOT be added to the sha256 comparator: `diffoscope --exclude` on a
packaged artifact (iso / ova / qcow2.xz) binary-falls-back on the outer container,
so excluding an inner member never yields "identical"; and an `--exclude` glob
that matches a root operand makes diffoscope skip the whole comparison (a false
PASS). Allowlist tolerance belongs in the diffoscope-descend comparator
(`help-steps/reproducible-compare`, currently on the `iso-build-fixes` branch);
unifying it with the sha256 path is a branch merge, not a flag on this runner.

