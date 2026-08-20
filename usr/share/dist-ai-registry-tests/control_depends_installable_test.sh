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
## imagehash (mediawiki-dom-snapshot, opt-in) is pip-only too -- neither is a
## Depends. This test keeps them (and their kind) out.
##
## Deterministic (no network): alternatives + a denylist + well-formed-name checks.
## When apt is fully populated it ALSO asserts every name has a live candidate.
## Source-tree test: set DIST_AI_REPO or run from a checkout; exits 77 (SKIP)
## without one.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

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
if [ -z "$(type -P grep-dctrl)" ]; then
   printf '%s\n' 'control-depends-installable-test: grep-dctrl (dctrl-tools) absent; skipping.' >&2
   exit 77
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

raw_depends="$(grep-dctrl --show-field=Depends --no-field-names '' "${control}")"

## --- Alternatives: no '|' in Depends ---
## here-string, not a pipe: a quiet grep on the reading end of a pipe is R-161.
if grep --quiet --fixed-strings -- '|' <<< "${raw_depends}"; then
   fail "Depends contains a '|' alternative -- deb-run-dep would require BOTH sides"
else
   pass "Depends has no '|' alternative"
fi

depends_names="$(printf '%s\n' "${raw_depends}" \
   | sed -e 's/,/ /g' -e 's/([^)]*)//g' -e 's/\[[^]]*\]//g' -e 's/${[^}]*}//g' \
   | tr -s ' \n' ' ')"

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
   case "${name}" in
      [a-z0-9]*[a-z0-9]|[a-z0-9])
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

## --- Optional: every name has an apt candidate (gated on a populated apt env) ---
apt_candidate() {
   local line
   while IFS= read -r line; do
      case "${line}" in
         *'Candidate:'*)
            line="${line#*Candidate: }"
            printf '%s' "${line%% *}"
            return 0
            ;;
      esac
   done < <(apt-cache policy "$1" 2>/dev/null)
}
if [ -n "$(type -P apt-cache)" ] \
   && [ -n "$(apt_candidate bash)" ] && [ -n "$(apt_candidate helper-scripts)" ]; then
   missing=''
   for name in ${depends_names}; do
      cand="$(apt_candidate "${name}")"
      if [ -z "${cand}" ] || [ "${cand}" = '(none)' ]; then
         missing="${missing} ${name}"
      fi
   done
   if [ -z "${missing}" ]; then
      pass 'every Depends name has an apt candidate'
   else
      fail "Depends names with NO apt candidate:${missing}"
   fi
else
   printf '%s\n' 'NOTE: apt sources not fully populated; skipped the live-candidate check' >&2
fi

printf '%s\n' "control-depends-installable-test: ${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ] || exit 1
