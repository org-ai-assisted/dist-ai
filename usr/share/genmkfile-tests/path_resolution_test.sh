#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## genmkfile's GENMKFILE_PATH resolution, and where its diagnostics go.
##
## genmkfile locates GENMKFILE_PATH -- from the environment, or by probing
## three candidate directories -- and then hands off to make-helper.bsh. What
## matters is WHICH path it resolved and WHETHER it handed off, so the handoff
## is recorded by a make-helper.bsh stub that prints its argv. An exit code
## alone cannot show a wrong path.
##
## Two failure shapes are covered because they are NOT the same:
##   - makefile-full unreadable: the directory lists fine, so the 'ls'
##     diagnostic succeeds and only the read fails;
##   - the DIRECTORY itself mode 0000: 'ls' on it fails too, which under
##     errexit aborted before the diagnostic could be printed. The fix is
##     'ls ... || true'. This one was found by review, not by the harness this
##     file replaces.
## Both must produce their diagnosis on STDERR, so stdout and stderr are
## captured SEPARATELY -- merged with 2>&1 a diagnostic moving from one to the
## other is invisible, and moving them was part of the change.
##
## NOT COVERED, deliberately: the detection-FAILURE path. Removing the
## fixture's share directory does not make detection fail, because the third
## candidate is the absolute '/usr/share/genmkfile', which exists on any
## machine with genmkfile installed. A case built that way silently exercises
## the SYSTEM installation instead of the fixture. Covering it properly needs
## the system path hidden, e.g. 'bwrap --dev-bind / / --tmpfs
## /usr/share/genmkfile', and is worth doing before relying on that branch.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v GENMKFILE_REPO ] || GENMKFILE_REPO=""

if [ -n "${GENMKFILE_REPO}" ]; then
   subject="${GENMKFILE_REPO}/usr/bin/genmkfile"
else
   subject='/usr/bin/genmkfile'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: genmkfile not found at '${subject}'" >&2
   printf '%s\n' "set GENMKFILE_REPO to a genmkfile checkout, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-path-test.XXXXXX")"

test_cleanup_handler() {
   ## A case leaves a 0000 directory behind; make the tree removable again.
   chmod --recursive u+rwX -- "${work_dir}" 2>/dev/null || true
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the stub body is LITERAL code written into a file.
# shellcheck disable=SC2016
prepare_root() {
   local state root

   state="$1"
   root="${work_dir}/root"
   chmod --recursive u+rwX -- "${root}" 2>/dev/null || true
   safe-rm --recursive --force -- "${root}"

   ## genmkfile walks two levels up from its own directory, so it must live at
   ## <root>/a/b/genmkfile for the probe to land on <root>.
   mkdir --parents -- "${root}/a/b"
   cp -- "${subject}" "${root}/a/b/genmkfile"
   chmod 0755 -- "${root}/a/b/genmkfile"

   case "${state}" in
      present|unreadable)
         mkdir --parents -- "${root}/usr/share/genmkfile"
         {
            printf '%s\n' '#!/bin/bash'
            printf '%s\n' 'printf "%s\n" "RAN make-helper $*"'
         } >"${root}/usr/share/genmkfile/make-helper.bsh"
         chmod 0755 -- "${root}/usr/share/genmkfile/make-helper.bsh"
         printf '%s\n' 'full' >"${root}/usr/share/genmkfile/makefile-full"
         if [ "${state}" = unreadable ]; then
            chmod 0000 -- "${root}/usr/share/genmkfile/makefile-full"
         fi
         ;;
      unlistable)
         ## Directory mode 0000: traversable by nobody, so 'ls' on it FAILS.
         ## Must be reached via an explicit GENMKFILE_PATH -- the auto-probe's
         ## own '[ -d ]' test would skip it and fall through.
         mkdir --parents -- "${root}/usr/share/genmkfile"
         chmod 0000 -- "${root}/usr/share/genmkfile"
         ;;
   esac
}

## SC2086: env_spec is a pre-split assignment list, deliberately unquoted.
# shellcheck disable=SC2086
run_genmkfile() {
   local state env_spec root status

   state="$1"
   env_spec="$2"
   prepare_root "${state}"
   root="${work_dir}/root"

   status=0
   ( cd -- "${root}" && env ${env_spec} timeout 15 \
      "${root}/a/b/genmkfile" some-target ) \
      >"${work_dir}/out" 2>"${work_dir}/err" || status=$?
   printf '%s' "${status}"
}

## check <description> <expect: handoff|diagnosed> <state> <env spec>
check() {
   local description expect state env_spec status stdout stderr verdict

   description="$1"
   expect="$2"
   state="$3"
   env_spec="$4"

   status="$(run_genmkfile "${state}" "${env_spec}")"
   stdout="$(cat -- "${work_dir}/out")"
   stderr="$(cat -- "${work_dir}/err")"

   verdict=PASS
   if printf '%s\n' "${stdout}${stderr}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort"
   elif [ "${expect}" = handoff ]; then
      if ! printf '%s\n' "${stdout}" | grep --fixed-strings -- 'RAN make-helper some-target' >/dev/null; then
         verdict=FAIL
         printf '%s\n' "FAIL: ${description}: make-helper.bsh was never handed the target"
      fi
   else
      ## The diagnosis must reach STDERR, and it must be GENMKFILE'S OWN --
      ## asserting merely that stderr is non-empty accepts bash's abort message
      ## from the very failure the fix prevents, so both pre-fix versions
      ## passed this case until the assertion named the text.
      ## Printing it on stdout would corrupt the output of any caller parsing
      ## genmkfile, which is why it moved to stderr.
      if ! printf '%s\n' "${stderr}" | grep --fixed-strings -- 'ERROR: Permission denied error? Try running:' >/dev/null; then
         verdict=FAIL
         printf '%s\n' "FAIL: ${description}: genmkfile's own diagnostic is not on stderr"
      fi
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description} (exit ${status})"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  stdout: $(printf '%s' "${stdout}" | tr '\n' '|' | head -c 150)"
      printf '%s\n' "  stderr: $(printf '%s' "${stderr}" | tr '\n' '|' | head -c 150)"
   fi
}

check 'GENMKFILE_PATH unset: ./usr/share is found' handoff \
   present '--unset=GENMKFILE_PATH'
check 'GENMKFILE_PATH set explicitly' handoff \
   present 'GENMKFILE_PATH=./usr/share/genmkfile'
check 'makefile-full unreadable is diagnosed on stderr' diagnosed \
   unreadable '--unset=GENMKFILE_PATH'
check 'an unlistable GENMKFILE_PATH is diagnosed on stderr' diagnosed \
   unlistable 'GENMKFILE_PATH=./usr/share/genmkfile'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
