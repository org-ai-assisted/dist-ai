#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pin that dist-ai's debian/control Depends stays installable as a set, i.e.
## 'genmkfile deb-run-dep'-safe. private-ai-config wires deb-run-dep into the
## sandbox-provision and claude-VM boot paths; it apt-installs the WHOLE Depends
## set in one all-or-nothing '--no-install-recommends' call, after a naive filter
## that strips '|' and version/arch qualifiers. Two shapes break it silently:
##   - an ALTERNATIVE 'A | B' -> filter yields two REQUIRED names 'A B', aborting
##     the install if either lacks a candidate. Alternatives belong in Recommends.
##   - a package with NO apt candidate (pip-only / not Debian-packaged) -> abort.
## WHY this exists: dist-ai once Depends'd on python3-imagehash and
## python3-playwright, NEITHER Debian-packaged, so the .deb was uninstallable and
## deb-run-dep failed wholesale -- while the suites still 'worked' because they
## exit 77 (SKIP) on an absent tool, so nobody noticed the .deb could not install.
## playwright is pip-installed into a venv by 'sandbox provision playwright';
## imagehash (mediawiki-dom-snapshot, opt-in) is pip-only -- neither is a
## Depends. This test keeps them (and their kind) out.
##
## Source-tree test: set DIST_AI_REPO or run from a checkout; exits 77 (SKIP)
## only when the SUBJECT (the dist-ai tree) is absent. Its required tooling
## (grep-dctrl, apt-get) is assumed present -- an absent one FAILS, it does not
## skip: 'an unauthorized skip is a failure, not green'.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
## No pathname expansion: package names are iterated unquoted, so a stray glob
## char in Depends (e.g. 'Depends: *') must stay literal to be judged, never
## expand against the CWD.
set -o noglob
## C locale for the WHOLE script: the well-formed-name check uses [a-z0-9] glob ranges
## whose membership is collation-dependent (under some locales [a-z] also matches
## uppercase, so an invalid 'Foobar' would read well-formed), and apt output must be
## stable to parse. One export covers both, so no per-command LC_ALL=C is needed.
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/debian/control" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -f "${repo}/debian/control" ]; then
   printf '%s\n' 'control-depends-installable-test: no dist-ai source tree (set DIST_AI_REPO); skipping.' >&2
   exit 77
fi
## 'type -P', not the house 'has': this test does not source helper-scripts,
## matching the sibling ci_config_test.sh. dctrl-tools is a declared Depends, so
## an absent grep-dctrl is a broken test environment -> FAIL, not a 77 skip.
if ! type -P grep-dctrl >/dev/null; then
   printf '%s\n' 'FAIL: control-depends-installable-test: grep-dctrl (dctrl-tools, a declared Depends) not on PATH; the gate cannot run' >&2
   exit 1
fi

control="${repo}/debian/control"

## Known NOT Debian-packaged (no apt candidate); pip/venv-provided. A name here must
## never sit in a Depends deb-run-dep installs. Extend as new ones are found.
denylist=(python3-playwright python3-imagehash)

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $1"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $1"
}

## BOTH Depends AND Pre-Depends: a non-installable name in either makes the .deb
## uninstallable, so both must clear these checks -- omitting Pre-Depends would be a
## FALSE GREEN (a bad Pre-Depends passing) of exactly the class this test catches.
raw_depends="$(grep-dctrl --show-field=Depends,Pre-Depends --no-field-names '' "${control}")"

## --- Alternatives: no '|' in Depends ---
## here-string, not a pipe: a quiet grep on the reading end of a pipe is R-161.
if grep --quiet --fixed-strings -- '|' <<< "${raw_depends}"; then
   fail "Depends contains a '|' alternative -- deb-run-dep would require BOTH sides"
else
   pass "Depends has no '|' alternative"
fi

## Package-name list. Strip, in order: commas, version '(...)', arch-restriction
## '[...]', substvars '${...}', and the multiarch ':qualifier' suffix (python3:any),
## so both the well-formed check and the candidate lookup see the bare name -- the
## same shape deb-run-dep hands to apt.
## Join continuation lines FIRST (tr '\n'), so a version '(...)' folded across a line
## boundary is stripped as one by the line-oriented sed.
depends_names="$(printf '%s' "${raw_depends}" \
   | tr '\n' ' ' \
   | sed -e 's/,/ /g' -e 's/([^)]*)//g' -e 's/\[[^]]*\]//g' -e 's/${[^}]*}//g' -e 's/:[a-z0-9-]*//g' \
   | tr -s ' ' ' ')"

## --- Denylist ---
deny_hit=''
for name in ${depends_names}; do
   for bad in "${denylist[@]}"; do
      [ "${name}" = "${bad}" ] && deny_hit="${name}"
   done
done
if [ -z "${deny_hit}" ]; then
   pass 'Depends lists no known non-Debian (pip-only) package'
else
   fail "Depends lists '${deny_hit}', which is not Debian-packaged (no apt candidate)"
fi

## --- Well-formed names ---
malformed=''
for name in ${depends_names}; do
   ## Debian policy: start with an alphanumeric; thereafter only [a-z0-9.+-]. A
   ## name may END in '+' (g++, clang++), so do not require a trailing alphanumeric.
   case "${name}" in
      [a-z0-9]*)
         ;;
      *)
         malformed="${name}"
         ;;
   esac
   case "${name}" in
      *[!a-z0-9.+-]*)
         malformed="${name}"
         ;;
   esac
done
if [ -z "${malformed}" ]; then
   pass 'every Depends name is a well-formed Debian package name'
else
   fail "Depends has a malformed package name: '${malformed}'"
fi

## --- The declared set installs together (REQUIRED, never a silent green) ---
## Faithful to what deb-run-dep actually does: apt-install the whole set in one
## '--no-install-recommends' call, gated on the EXIT CODE (not parsed output) -- so it
## is correct for virtual packages / providers (apt resolves a single-provider virtual,
## and aborts a multi-provider one exactly as deb-run-dep would). 'apt-get --simulate'
## needs no root. (LC_ALL=C is set script-wide in the preamble.)
if [ -z "${depends_names// /}" ]; then
   ## Only substvars (e.g. ${misc:Depends}) -> no explicit names to verify. Trivially
   ## installable, and do NOT hand apt-get an empty operand list (behaviour varies by
   ## apt version). The other checks above equally no-op here, so this masks nothing new.
   pass 'no explicit Depends/Pre-Depends names to verify (substvars only)'
elif ! type -P apt-get >/dev/null; then
   fail 'apt-get not on PATH; cannot verify Depends installability'
elif ! apt-get install --simulate --no-install-recommends -- bash helper-scripts >/dev/null 2>&1; then
   ## Sentinel: a Debian package (bash) and a Kicksecure one (helper-scripts, itself a
   ## declared Depends) must resolve, proving the apt lists are populated for BOTH
   ## archives. Without it, a minimal container with cleaned/absent lists would fail a
   ## VALID control on the set-simulate with a misleading per-package "unable to locate".
   ## Report the real cause -- still a FAIL (never a false green), just honest.
   fail 'apt lists empty/incomplete (bash/helper-scripts do not resolve); cannot verify Depends installability -- not a control fault'
else
   ## noglob (set above) lets ${depends_names} split into args without expanding.
   # shellcheck disable=SC2086
   if sim_out="$(apt-get install --simulate --no-install-recommends -- ${depends_names} 2>&1)"; then
      pass 'the declared Depends set installs together (apt-get --simulate)'
   else
      fail 'the declared Depends set does not install together (apt-get --simulate); apt says:'
      ## Best-effort diagnostic (|| true: a no-match grep must not abort under pipefail).
      printf '%s\n' "${sim_out}" \
         | grep --ignore-case --extended-regexp 'unable to locate|no installation candidate|but it is not|^E:' \
         | head -5 >&2 || true
   fi
fi

printf '%s\n' "control-depends-installable-test: ${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ] || exit 1
