#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## reproduce-in-docker (dist-encrypted-tests) CREATES the reproduction container; every CONSUMER
## tool (server-test-all, wiki-csp-render-test, ...) resolves REPRO_CONTAINER via the shared
## repro-container-defaults lib. The creator MUST resolve it the same way: a session that exports
## REPRO_CONTAINER for an ISOLATED container needs the creator to build + force-remove THAT name, not
## the SHARED canonical one -- a creator that hardcodes the canonical clobbers a concurrent session's
## repro. This drives the REAL script's --preflight-only (no docker, no mutation, runs anywhere) and
## asserts the resolved container name follows REPRO_CONTAINER.
##
## Two canary points, both RED on the pre-fix script:
##   1. REPRO_CONTAINER=<custom> -> the preflight must report <custom>, not the canonical default
##      (the hardcoded-canonical bug reported the canonical here).
##   2. --preflight-only must RUN FROM A CHECKOUT: repro-container-defaults is sourced from the
##      dist-encrypted sibling when it is not installed beside this script (the old source-next-to-
##      self-only line could not resolve the lib from a checkout, so the preflight aborted).
##
## The dist-encrypted sibling (repro-container-defaults + the per-wiki trust-root files) is an
## OPTIONAL component checkout; absent -> SKIP (77), matching rsync_delete_versions_test.sh.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Subject: the dist-encrypted-tests checkout (DIST_ENCRYPTED_TESTS_REPO, wired by
## dist-ai-tests-all) or the installed copy.
if [ -n "${DIST_ENCRYPTED_TESTS_REPO:-}" ]; then
   subject="${DIST_ENCRYPTED_TESTS_REPO}/usr/local/bin/reproduce-in-docker"
else
   subject='/usr/local/bin/reproduce-in-docker'
fi
if [ ! -x "${subject}" ]; then
   printf '%s\n' "reproduce-in-docker not executable at '${subject}' (set DIST_ENCRYPTED_TESTS_REPO); skipping." >&2
   ## style-ok: allow-skip: dist-encrypted-tests target unavailable (optional component checkout)
   exit 77
fi

## The dist-encrypted sibling supplies repro-container-defaults (the shared resolver) + the per-wiki
## trust-root files the preflight validates. DIST_ENCRYPTED_REPO overrides; else the sibling laid
## out next to the dist-encrypted-tests checkout.
if [ -n "${DIST_ENCRYPTED_REPO:-}" ]; then
   de_repo="${DIST_ENCRYPTED_REPO}"
else
   de_repo="$(cd -- "$(dirname -- "${subject}")/../../.." && pwd)/dist-encrypted"
fi
defaults_lib="${de_repo}/usr/local/bin/repro-container-defaults"
if [ ! -r "${defaults_lib}" ]; then
   printf '%s\n' "repro-container-defaults not readable at '${defaults_lib}' (set DIST_ENCRYPTED_REPO); skipping." >&2
   ## style-ok: allow-skip: dist-encrypted sibling unavailable (optional component checkout)
   exit 77
fi

## The canonical container name comes from the lib itself, so this fixture can never drift from the
## real default (a drift would silently make the default-case assertion vacuous). Sourced in a
## command-substitution subshell so the lib's definitions never leak into this test shell; the
## quoted path is data, so a checkout path with shell metacharacters is safe.
# shellcheck disable=SC1090,SC2154  # dynamic lib path; repro_container_canonical is set by that lib
canonical="$(source "${defaults_lib}"; printf '%s' "${repro_container_canonical}")"
if [ -z "${canonical}" ]; then
   printf '%s\n' "FATAL: could not read repro_container_canonical from '${defaults_lib}'" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

## A launch-systemd-container.sh stub: --preflight-only only CHECKS it exists + is executable (it
## prints the path in the plan); it never INVOKES it (that is the real docker/systemd launch, gated
## behind the non-preflight path). A stub keeps the dry layout check hermetic (no developer-meta-
## files checkout, no privileged launch).
dmf_dir="${test_dir}/dmf"
mkdir --parents -- "${dmf_dir}/.github/actions/launch-systemd-container"
launch_stub="${dmf_dir}/.github/actions/launch-systemd-container/launch-systemd-container.sh"
cat > "${launch_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "launch-systemd-container stub: --preflight-only must never invoke this" >&2
exit 1
STUB
chmod +x -- "${launch_stub}"

pass=0
fail=0
check() {
   local label got want
   label="$1"; got="$2"; want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"; pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')" >&2; fail=$((fail + 1))
   fi
}

## Run the REAL script's --preflight-only; capture status + output. $1 = REPRO_CONTAINER ("" unset).
run_preflight() {
   run_rc=0
   if [ -n "$1" ]; then
      run_out="$(REPRO_CONTAINER="$1" DIST_ENCRYPTED_REPO="${de_repo}" DMF_DIR="${dmf_dir}" \
         "${subject}" local --preflight-only 2>&1)" || run_rc=$?
   else
      ## Explicitly UNSET REPRO_CONTAINER (not merely leave it unset in the prefix): the ambient
      ## environment may already export it -- this very session runs under an isolated REPRO_CONTAINER
      ## -- which would leak in and make the canonical-default assertion assert the ambient name.
      run_out="$(env --unset=REPRO_CONTAINER DIST_ENCRYPTED_REPO="${de_repo}" DMF_DIR="${dmf_dir}" \
         "${subject}" local --preflight-only 2>&1)" || run_rc=$?
   fi
}

## The 'container name  : <name>' plan line (tolerant of the exact column spacing).
reported_container() {
   printf '%s\n' "$1" | sed -n 's/^[[:space:]]*container name[[:space:]]*:[[:space:]]*//p' | head -n 1
}

## ===== default: no REPRO_CONTAINER -> the canonical shared name =====
## Also the from-checkout guard: a clean rc 0 + 'preflight OK' proves the lib was sourced from the
## sibling (the old source-next-to-self-only line aborted here from a checkout).
run_preflight ""
check "preflight (default) exits 0 -- lib resolved from the dist-encrypted sibling (from-checkout guard)" \
   "${run_rc}" "0"
check "preflight (default) reaches 'preflight OK'" \
   "$(printf '%s' "${run_out}" | grep -c 'preflight OK')" "1"
check "default container name is the canonical shared name" \
   "$(reported_container "${run_out}")" "${canonical}"

## ===== REPRO_CONTAINER set -> the creator uses THAT name (isolated), never the canonical =====
## CANARY: a creator that hardcodes the canonical reports it here and clobbers the shared container.
isolated="dist-encrypted-reproduce-isolation-canary"
## Sanity: the isolated name differs from the canonical, so the assertion is meaningful.
if [ "${isolated}" != "${canonical}" ]; then
   differ=yes
else
   differ=no
fi
check "canary name differs from the canonical default" "${differ}" "yes"
run_preflight "${isolated}"
check "preflight (REPRO_CONTAINER set) exits 0" "${run_rc}" "0"
check "REPRO_CONTAINER is honored -- the creator targets the isolated container, not the canonical" \
   "$(reported_container "${run_out}")" "${isolated}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
