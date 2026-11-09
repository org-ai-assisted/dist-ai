#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-image-test orchestrator: every lane runs dm-release-test on the server (server-exec), and
## test-results-deploy publishes EXACTLY ONCE on exit (via the EXIT trap) -- even on a lane failure
## -- so publishing is never forgotten. --no-publish opts out. server-exec + test-results-deploy
## are stubbed (recording fakes); no server, no network, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

bin="${VBOX_IMAGE_TEST_BIN:-vbox-image-test}"
[ -x "${bin}" ] || { printf '%s\n' "FATAL: vbox-image-test not executable at '${bin}'" >&2; exit 1; }

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: ${1}"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: ${1}"; }
want() {
   ## want <actual> <expected> <label>
   if [ "${1}" = "${2}" ]; then
      pass "${3} (${1})"
   else
      fail "${3}: got '${1}', want '${2}'"
   fi
}

work="$(mktemp --directory)"
# shellcheck disable=SC2317  # invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT

## Stub server-exec (records each --cmd value = the dm-release-test lane) and test-results-deploy
## (counts calls). Both read their recording path + exit code from the environment.
stub="${work}/stub"
mkdir --parents -- "${stub}"
cat > "${stub}/server-exec" <<'STUB'
#!/bin/bash
prev=""
for a in "$@"; do
   [ "${prev}" = "--cmd" ] && printf '%s\n' "${a}" >> "${SE_LANES}"
   prev="${a}"
done
## Record the FULL argv (to assert each lane carries --timeout 0 --wait) and a lane marker in the
## shared order log (to assert the publish runs only AFTER every lane dispatch). Both seams default
## to /dev/null so the cases that do not set them are unaffected.
printf '%s\n' "$*" >> "${SE_ARGV:-/dev/null}"
printf '%s\n' lane >> "${ORDER:-/dev/null}"
exit "${SE_RC:-0}"
STUB
cat > "${stub}/test-results-deploy" <<'STUB'
#!/bin/bash
printf 'x' >> "${TRD_CALLS}"
printf '%s\n' publish >> "${ORDER:-/dev/null}"
exit "${TRD_RC:-0}"
STUB
chmod +x -- "${stub}/server-exec" "${stub}/test-results-deploy"
export PATH="${stub}:${PATH}"

lanes="${work}/lanes"
calls="${work}/calls"
argv="${work}/argv"
order="${work}/order"
reset() { true > "${lanes}"; true > "${calls}"; true > "${argv}"; true > "${order}"; }
n_lanes() { grep --count 'dm-release-test' "${lanes}" 2>/dev/null || printf '%s' 0; }
n_calls() { wc --bytes < "${calls}" 2>/dev/null | tr --delete ' '; }

# --- two lanes: both run, publish exactly once ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" "kicksecure lxqt --iso /x.iso" "whonix lxqt --lane inst" || rc=$?
want "${rc}" 0 "two lanes -> rc 0"
want "$(n_lanes)" 2 "both lanes ran dm-release-test"
want "$(n_calls)" 1 "published exactly once for the batch"

# --- a lane FAILS: publish STILL runs (EXIT trap), failure propagates ---
reset
rc=0
SE_RC=1 SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" "kicksecure lxqt --iso /x.iso" || rc=$?
if [ "${rc}" -ne 0 ]; then pass "lane failure -> non-zero rc (${rc})"; else fail "lane failure masked (rc 0)"; fi
want "$(n_calls)" 1 "publish runs even on a lane failure"

# --- single lane: runs it, publishes once ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" "kicksecure lxqt --iso /x.iso" || rc=$?
want "${rc}" 0 "single lane -> rc 0"
want "$(n_lanes)" 1 "single lane ran dm-release-test"
want "$(n_calls)" 1 "single lane published once"

# --- --no-publish: no deploy ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" --no-publish "kicksecure lxqt --iso /x.iso" || rc=$?
want "${rc}" 0 "--no-publish -> rc 0"
want "$(n_calls)" 0 "--no-publish skips the deploy"

# --- grok#3: a lane token with a shell metachar is %q-escaped into the remote --cmd, never
#     spliced raw (server-exec --cmd runs as a remote root bash script). Canary: old code spliced
#     ${spec} raw, so the recorded cmd held a bare 'a;b'; now it is 'a\;b'. ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" --no-publish 'kicksecure lxqt --version a;b' || rc=$?
want "${rc}" 0 "metachar lane -> rc 0"
if grep --quiet --fixed-strings 'a\;b' "${lanes}"; then pass "metachar token %q-escaped in the remote cmd"; else fail "metachar token NOT escaped -- a raw ';' would execute on the server as root"; fi
if grep --quiet --fixed-strings 'version a;b' "${lanes}"; then fail "raw unescaped 'a;b' spliced into the remote cmd"; else pass "no raw unescaped metachar token in the remote cmd"; fi

# --- D: --local-repo is appended to a `whonix cli --lane  inst` lane with REPEATED spaces.
#     Canary: the old match globbed the literal " --lane inst " (single spaces), so a lane with
#     `--lane  inst` dropped --local-repo while the inst lane still ran -- silently testing the
#     PUBLISHED packages instead of the local build. Match after the same whitespace split
#     dm-release-test applies, so spacing cannot drop the flag. ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" --no-publish --local-repo whonix 'whonix cli --lane  inst --version 18' || rc=$?
want "${rc}" 0 "double-space inst lane -> rc 0"
if grep --quiet --fixed-strings -- '--local-repo whonix' "${lanes}"; then pass "double-space --lane inst got --local-repo appended"; else fail "double-space --lane inst DROPPED --local-repo (would test published packages, not the local build)"; fi

# --- D companion: a single-space inst lane also gets it; a NON-inst whonix cli lane does not. ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" --no-publish --local-repo whonix 'whonix cli --lane inst --version 18' || rc=$?
if grep --quiet --fixed-strings -- '--local-repo whonix' "${lanes}"; then pass "single-space --lane inst got --local-repo appended"; else fail "single-space --lane inst did not get --local-repo"; fi
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" --no-publish --local-repo whonix 'whonix cli --version 18' || rc=$?
if grep --quiet --fixed-strings -- '--local-repo whonix' "${lanes}"; then fail "non-inst whonix cli lane wrongly got --local-repo"; else pass "non-inst whonix cli lane left unchanged"; fi

# --- no lanes: usage error ---
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" >/dev/null 2>&1 || rc=$?
want "${rc}" 64 "no lanes -> usage rc 64"

# --- W6: a lane spec with a newline is rejected (exit 64) BEFORE any publish -- the local
#     read -r -a would otherwise truncate it and silently drop the tail args. ---
reset
rc=0
nlspec="kicksecure lxqt"$'\n'"--iso /x.iso"
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" "${nlspec}" >/dev/null 2>&1 || rc=$?
want "${rc}" 64 "newline-bearing lane rejected (exit 64)"
want "$(n_calls)" 0 "newline rejection does not publish"

# --- a lane spec with a quote is rejected (exit 64) before any publish -- read -r -a keeps the
#     quote as a literal and splits a spaced path, so a clear reject here beats a confusing
#     downstream dm-release-test arg error (a path in a lane must be space-free). ---
reset
rc=0
SE_LANES="${lanes}" TRD_CALLS="${calls}" "${bin}" 'kicksecure lxqt --iso "/built image.iso"' >/dev/null 2>&1 || rc=$?
want "${rc}" 64 "quoted lane spec rejected (exit 64)"
want "$(n_calls)" 0 "quote rejection does not publish"

# --- each lane is dispatched with `--timeout 0 --wait` so the real server-exec detaches durably
#     yet BLOCKS on the lane's real rc -- restoring sequential order + a true verdict and making
#     the publish fire only after lanes are terminal. Canary: pre-fix argv was `--timeout 0 --cmd`
#     with NO --wait, so server-exec returned 0=launched and the publish fired on stale results. ---
reset
rc=0
SE_LANES="${lanes}" SE_ARGV="${argv}" ORDER="${order}" TRD_CALLS="${calls}" \
   "${bin}" --no-publish "kicksecure lxqt --iso /x.iso" "whonix lxqt --lane inst" || rc=$?
want "${rc}" 0 "wait-dispatch lanes -> rc 0"
n_argv="$(grep --count . "${argv}" 2>/dev/null || printf '%s' 0)"
want "${n_argv}" 2 "both lanes invoked server-exec"
if [ "$(grep --count -- '--wait' "${argv}")" = 2 ] && ! grep --quiet --invert-match -- '--wait' "${argv}"; then
   pass "every lane dispatched with --wait"
else
   fail "a lane dispatched WITHOUT --wait -- server-exec would return 0=launched (false green, premature publish)"
fi
if [ "$(grep --count -- '--timeout 0' "${argv}")" = 2 ]; then pass "every lane keeps --timeout 0 (never kill a 40-50 min lane)"; else fail "a lane lost --timeout 0"; fi

# --- the publish runs strictly AFTER every lane dispatch (EXIT trap at end), never interleaved. ---
reset
rc=0
SE_LANES="${lanes}" SE_ARGV="${argv}" ORDER="${order}" TRD_CALLS="${calls}" \
   "${bin}" "kicksecure lxqt --iso /x.iso" "whonix lxqt --lane inst" || rc=$?
want "$(tr '\n' ' ' < "${order}")" "lane lane publish " "publish logged only after both lane dispatches"

printf '%s\n' "----"
printf '%s\n' "passed=${pass_count} failed=${fail_count}"
[ "${fail_count}" -eq 0 ]
