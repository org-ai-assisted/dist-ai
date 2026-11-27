#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL sudoers-command-audit tool against built fixtures and asserts
## its findings and exit codes. cvtsudoers (the 'sudo' package) is a hard
## dependency of the tool; it is assumed present and called directly, so its
## absence fails the assertions loudly rather than skipping. Every "detect a
## dangling command" assertion is paired with a canary (same fixture, command
## now present -> must go clean) so a tool that always passes, or always fails,
## cannot read green.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## --- locate the subject tool ------------------------------------------------
## DIST_AI_REPO set (orchestrated run): REQUIRE that checkout's tool -- never
## silently fall back to a stale installed copy that could not judge this
## checkout. Unset (direct run): prefer the checkout-relative tool over any
## installed one so a standalone run still tests the changed tool.
payload_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
if [ -n "${DIST_AI_REPO:-}" ]; then
  subject="${DIST_AI_REPO}/usr/bin/sudoers-command-audit"
  if [ ! -x "${subject}" ]; then
    printf '%s\n' \
      "FATAL: sudoers-command-audit-tests: DIST_AI_REPO set but ${subject} is not executable." >&2
    exit 1
  fi
  subject="$(readlink --canonicalize -- "${subject}")"
else
  subject=''
  for candidate in \
    "${payload_dir}/../../bin/sudoers-command-audit" \
    '/usr/bin/sudoers-command-audit'; do
    if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
    fi
  done
  if [ -z "${subject}" ]; then
    printf '%s\n' "FATAL: sudoers-command-audit-tests: subject tool not found." >&2
    exit 1
  fi
fi

## cvtsudoers (the 'sudo' package) is a hard dependency in debian/control and is
## assumed present: the tool is driven directly and fails loud (returns 2, so
## the assertions below fail) if it is ever absent -- no has/die preflight.

[ -v TMP ] || TMP=/tmp
work="$(mktemp --directory -- "${TMP}/sudoers-command-audit-test.XXXXXX")"

cleanup() {
  safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

pass=0
fail=0
out=''
code=0

## run the subject, capturing stdout + exit code into globals.
run_audit() {
  out=''
  code=0
  out="$( "${subject}" "$@" 2>/dev/null )" || code=$?
}

## predicates: return 0 when the assertion holds. Herestrings, not pipes, so a
## quiet grep never consumes a pipe (R-161).
rc_is() {
  [ "${code}" -eq "$1" ]
}
out_empty() {
  [ -z "${out}" ]
}
out_has() {
  grep --quiet --fixed-strings -- "$1" <<< "${out}"
}
out_lacks() {
  ! grep --quiet --fixed-strings -- "$1" <<< "${out}"
}

check() {
  local desc="$1"
  shift
  if "$@"; then
    pass=$(( pass + 1 ))
  else
    fail=$(( fail + 1 ))
    printf '%s\n' "FAIL: ${desc}" >&2
    printf '%s\n' "      exit=${code} output=<<${out}>>" >&2
  fi
}

## --- fixtures ----------------------------------------------------------------
root="${work}/root"
mkdir -p -- "${root}/usr/bin"
printf '%s\n' '#!/bin/sh' > "${root}/usr/bin/present"
chmod +x -- "${root}/usr/bin/present"
printf '%s\n' 'data' > "${root}/usr/bin/nonexec"

cat > "${work}/clean" <<'EOF'
user ALL=NOPASSWD: /usr/bin/present
user ALL=NOPASSWD: /usr/bin/present dist-upgrade
user ALL=(ALL) ALL
%sudo ALL=NOPASSWD: sudoedit /etc/hosts
EOF

cat > "${work}/plain-missing" <<'EOF'
user ALL=NOPASSWD: /usr/bin/gone-cmd arg1
EOF

cat > "${work}/alias-missing" <<'EOF'
Cmnd_Alias UPD = /usr/bin/present, /usr/bin/gone-alias-member
user ALL=NOPASSWD: UPD
EOF

cat > "${work}/negated-missing" <<'EOF'
user ALL=NOPASSWD: !/usr/bin/gone-negated
EOF

printf '%s\n' 'this is not valid sudoers @@@' > "${work}/broken"

## a sysroot for the default-mode (no-double-report) check: a main sudoers with
## no includedir plus an unrelated drop-in.
sysroot="${work}/sysroot"
mkdir -p -- "${sysroot}/etc/sudoers.d" "${sysroot}/usr/bin"
cat > "${sysroot}/etc/sudoers" <<'EOF'
user ALL=NOPASSWD: /usr/bin/gone-main
EOF
cat > "${sysroot}/etc/sudoers.d/extra" <<'EOF'
user ALL=NOPASSWD: /usr/bin/gone-dropin
EOF

## --- assertions --------------------------------------------------------------

## 1. clean fixture: args stripped, ALL and sudoedit skipped -> exit 0, no output.
run_audit --root "${root}" "${work}/clean"
check "clean fixture passes (exit 0)" rc_is 0
check "clean fixture prints no findings" out_empty

## 2. plain missing command (with args) detected.
run_audit --root "${root}" "${work}/plain-missing"
check "missing command detected (exit 1)" rc_is 1
check "missing command path named in output" out_has '/usr/bin/gone-cmd'

## 2-canary: create the command under the root -> must now go clean. Proves the
## "missing" verdict is genuinely sensitive to presence, not a constant.
printf '%s\n' '#!/bin/sh' > "${root}/usr/bin/gone-cmd"
chmod +x -- "${root}/usr/bin/gone-cmd"
run_audit --root "${root}" "${work}/plain-missing"
check "canary: command present -> clean (exit 0)" rc_is 0
safe-rm --force -- "${root}/usr/bin/gone-cmd"

## 3. Cmnd_Alias member existence is checked (present member fine, missing flagged).
run_audit --root "${root}" "${work}/alias-missing"
check "alias member missing detected (exit 1)" rc_is 1
check "missing alias member named in output" out_has '/usr/bin/gone-alias-member'
check "present alias member not flagged" out_lacks '/usr/bin/present'

## 4. negated (deny) rule to a missing command detected and tagged.
run_audit --root "${root}" "${work}/negated-missing"
check "negated missing detected (exit 1)" rc_is 1
check "negated finding tagged 'deny rule'" out_has 'deny rule'

## 5. unparseable source -> inconclusive (exit 2), never a false clean.
run_audit --root "${root}" "${work}/broken"
check "parse error is inconclusive (exit 2)" rc_is 2

## 6. --require-executable: present-but-not-executable.
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/nonexec' > "${work}/nonexec-rule"
run_audit --root "${root}" "${work}/nonexec-rule"
check "non-executable command not flagged by default (exit 0)" rc_is 0
run_audit --root "${root}" --require-executable "${work}/nonexec-rule"
check "non-executable flagged with --require-executable (exit 1)" rc_is 1
check "non-executable finding tagged 'not executable'" out_has 'not executable'

## 7. --find discovers drop-ins and honours sudo's ignore rule (dot/tilde names).
tree="${work}/tree"
mkdir -p -- "${tree}/etc/sudoers.d"
cp -- "${work}/plain-missing" "${tree}/etc/sudoers.d/live"
cp -- "${work}/plain-missing" "${tree}/etc/sudoers.d/live.disabled"
run_audit --root "${root}" --find "${tree}"
check "--find detects a dangling command in a loadable drop-in (exit 1)" rc_is 1
check "--find audits the loadable drop-in" out_has 'etc/sudoers.d/live:'
check "--find ignores a '.'-containing drop-in name" out_lacks 'live.disabled'

## 8. default mode (no positional, no --find) audits only <root>/etc/sudoers.
##    On a real system cvtsudoers follows its @includedir, so the drop-ins are
##    covered in that one parse; feeding the directory a second time would
##    double-report every finding. This fixture's main file has no includedir,
##    so the drop-in's command must be ABSENT from the result -- the regression
##    guard for the double-report bug.
run_audit --root "${sysroot}"
check "default mode detects the main sudoers finding (exit 1)" rc_is 1
check "default mode flags the main-file command" out_has '/usr/bin/gone-main'
check "default mode does not separately feed /etc/sudoers.d" out_lacks '/usr/bin/gone-dropin'

## 9. existence is resolved CONFINED to --root: an absolute symlink inside the
##    image must not be followed to the host filesystem (the false-clean bug),
##    while a relative symlink resolving within the image is present.
imgroot="${work}/imgroot"
mkdir -p -- "${imgroot}/usr/bin" "${imgroot}/etc/sudoers.d"
printf '%s\n' '#!/bin/sh' > "${work}/outside-target"
chmod +x -- "${work}/outside-target"
## absolute target that exists on the real fs but is OUTSIDE imgroot.
ln -s -- "${work}/outside-target" "${imgroot}/usr/bin/escaping"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/escaping' > "${imgroot}/etc/sudoers.d/esc"
printf '%s\n' '#!/bin/sh' > "${imgroot}/usr/bin/realbin"
chmod +x -- "${imgroot}/usr/bin/realbin"
ln -s realbin "${imgroot}/usr/bin/reltool"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/reltool' > "${imgroot}/etc/sudoers.d/rel"
run_audit --root "${imgroot}" "${imgroot}/etc/sudoers.d/esc"
check "absolute symlink escaping root is flagged, not followed to host (exit 1)" rc_is 1
check "escaping command is named" out_has '/usr/bin/escaping'
run_audit --root "${imgroot}" "${imgroot}/etc/sudoers.d/rel"
check "relative symlink resolving within root is present (exit 0)" rc_is 0

## 10. a command PATH that legitimately contains a (backslash-escaped) space is
##     matched via progressive prefixes, not mis-split on the first space.
mkdir -p -- "${root}/opt/my dir"
printf '%s\n' '#!/bin/sh' > "${root}/opt/my dir/tool"
chmod +x -- "${root}/opt/my dir/tool"
printf '%s\n' 'user ALL=NOPASSWD: /opt/my\ dir/tool' > "${work}/spaced"
run_audit --root "${root}" "${work}/spaced"
check "spaced command path matched, not mis-split (exit 0)" rc_is 0

## 11. an escaped-space command PATH whose real file is absent is NOT masked by
##     an existing shorter prefix: the boundary is recovered, so a bare prefix
##     no longer reads as the command (the dangling-grant false-clean).
printf '%s\n' '#!/bin/sh' > "${root}/opt/tool"
chmod +x -- "${root}/opt/tool"
printf '%s\n' 'user ALL=NOPASSWD: /opt/tool\ old subcmd' > "${work}/prefix-mask"
run_audit --root "${root}" "${work}/prefix-mask"
check "spaced path removed, prefix present -> missing (exit 1)" rc_is 1
check "spaced command named in full, not its prefix" out_has '/opt/tool old'
run_audit --root "${root}" --require-executable "${work}/prefix-mask"
check "removed spaced path still missing with --require-executable (exit 1)" rc_is 1
## 11-canary: create the real spaced command -> now clean (verdict is genuinely
## sensitive to the full path, not satisfied by the executable prefix).
printf '%s\n' '#!/bin/sh' > "${root}/opt/tool old"
chmod +x -- "${root}/opt/tool old"
run_audit --root "${root}" "${work}/prefix-mask"
check "canary: spaced command present -> clean (exit 0)" rc_is 0
safe-rm --force -- "${root}/opt/tool old" "${root}/opt/tool"

## 12. --find over a search tree that cannot be fully read is inconclusive, not
##     clean: a silently-omitted tree must never let the audit pass.
findtree="${work}/findtree"
mkdir -p -- "${findtree}/etc/sudoers.d"
cp -- "${work}/clean" "${findtree}/etc/sudoers.d/ok"
run_audit --root "${root}" --find "${findtree}"
check "readable --find tree alone is not inconclusive (exit 0)" rc_is 0
run_audit --root "${root}" --find "${findtree}" "${work}/no-such-tree"
check "an unreadable search tree -> inconclusive (exit 2)" rc_is 2

## 13. a source that @includes an absolute path under a non-default --root is
##     inconclusive: cvtsudoers would resolve the include against the HOST, not
##     the image, so the parse is not faithful and must not read as clean.
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/present' '@includedir /etc/sudoers.d' \
  > "${work}/with-include"
run_audit --root "${root}" "${work}/with-include"
check "@include under --root -> inconclusive (exit 2)" rc_is 2
## 13-canary: the same rule without the include audits normally (not inconclusive).
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/present' > "${work}/no-include"
run_audit --root "${root}" "${work}/no-include"
check "no include -> audited, not inconclusive (exit 0)" rc_is 0

## 14. a wildcard command path is reported INCONCLUSIVE: matching sudo's
##     glob(3)/fnmatch semantics AND confining the match to --root is beyond this
##     audit, so it refuses rather than risk a false clean (an unconfined glob
##     escaping --root to a host binary) or a false missing. A present match no
##     longer reads as clean (exit 0) -- the glob-escape false-clean.
printf '%s\n' '#!/bin/sh' > "${root}/usr/bin/globbed-tool"
chmod +x -- "${root}/usr/bin/globbed-tool"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/globbed-*' > "${work}/wildcard"
run_audit --root "${root}" "${work}/wildcard"
check "wildcard command path with a match is inconclusive, not clean (exit 2)" rc_is 2
safe-rm --force -- "${root}/usr/bin/globbed-tool"
run_audit --root "${root}" "${work}/wildcard"
check "wildcard command path with no match is still inconclusive (exit 2)" rc_is 2

## 15. two distinct spaced command paths sharing a first token are each named in
##     full, not collapsed to that token and deduplicated to one finding.
printf '%s\n' \
  'user ALL=NOPASSWD: /opt/My\ App/tool' \
  'user ALL=NOPASSWD: /opt/My\ Other/tool' > "${work}/spaced-pair"
run_audit --root "${root}" "${work}/spaced-pair"
check "both spaced commands missing (exit 1)" rc_is 1
check "first spaced command named in full" out_has '/opt/My App/tool'
check "second spaced command named in full" out_has '/opt/My Other/tool'

## 16. a RELATIVE @include is resolved faithfully by cvtsudoers from the source
##     file's own directory (not the host namespace), so it is NOT a coverage
##     gap: the including file's own commands are still audited and a missing one
##     is reported, never masked as inconclusive.
mkdir -p -- "${work}/relinc"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/present' > "${work}/relinc/extra"
printf '%s\n' 'user ALL=NOPASSWD: /no/such/relbin' '@include extra' \
  > "${work}/relinc/policy"
run_audit --root "${root}" "${work}/relinc/policy"
check "relative @include not inconclusive; own missing cmd found (exit 1)" rc_is 1
check "missing command in a relative-include file named" out_has '/no/such/relbin'

## 17. an ABSOLUTE @includedir on the live root (--root /) that this process
##     cannot read is inconclusive: cvtsudoers SILENTLY drops an unreadable
##     includedir (rc 0, no warning; sudo as root would still load it), so
##     trusting the exit-0 parse would be a false clean. /usr/bin/true is the
##     directly-named command, so the ONLY reason it is not clean is the gap.
incdir="${work}/abs-inc-dir"
mkdir -p -- "${incdir}"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/true' > "${incdir}/drop"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/true' "@includedir ${incdir}" \
  > "${work}/live-include"
chmod 000 -- "${incdir}"
run_audit "${work}/live-include"
check "unreadable absolute @includedir on live root -> inconclusive (exit 2)" rc_is 2
chmod 755 -- "${incdir}"
## 17-canary: the same source with the include directive REMOVED audits clean,
## proving the inconclusive verdict comes from the unreadable include, not the
## directly-named command.
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/true' > "${work}/live-no-include"
run_audit "${work}/live-no-include"
check "canary: no include -> audited clean (exit 0)" rc_is 0

## 18. boundary recovery is PER-RULE: one rule's escaped-space path must never be
##     applied to another rule's command string. Rule A's spaced path
##     '/usr/bin/foo bar' is PRESENT; rule B grants '/usr/bin/foo' with arguments
##     and '/usr/bin/foo' is ABSENT. The old file-global prefix match reported B
##     clean by borrowing A's present spaced path (a dead-grant false clean); the
##     per-rule map checks B's real '/usr/bin/foo' and reports it missing.
printf '%s\n' '#!/bin/sh' > "${root}/usr/bin/foo bar"
chmod +x -- "${root}/usr/bin/foo bar"
printf '%s\n' \
  'user ALL=NOPASSWD: /usr/bin/foo\ bar' \
  'user ALL=NOPASSWD: /usr/bin/foo bar baz' > "${work}/per-rule"
run_audit --root "${root}" "${work}/per-rule"
check "cross-rule spaced-path contamination -> B's dead grant found (exit 1)" rc_is 1
check "B's real command /usr/bin/foo named" out_has 'missing: /usr/bin/foo'
check "A's present spaced path not misreported missing" out_lacks '/usr/bin/foo bar'
safe-rm --force -- "${root}/usr/bin/foo bar"

## --- report ------------------------------------------------------------------
printf '%s\n' "sudoers-command-audit-tests: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
