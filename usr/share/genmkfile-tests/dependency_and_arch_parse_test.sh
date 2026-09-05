#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make-helper-one.bsh debian/control parsing:
##  - make_dependencies_filter_helper (flat, no alternative-parsing): must not collapse a
##    space-less 'A|B' to 'AB', and must strip build-profile '<...>' and any '${...}' substvar.
##  - make_get_variables_parse_stanzas' Package/Architecture loop maps each stanza to the
##    expected .deb (single-line fields; not folded) and rejects an unsafe control-derived
##    package name before it reaches a deletion path.
##
## make-helper-one.bsh is sourceable (its main is was_executed-guarded), so we source it once
## and call these functions directly -- no sed extraction, no sentinel-delimited blocks.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC2317
error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}
trap error_handler ERR

locate_helper() {
   local candidate from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
   fi
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${from_bin}" \
      "${HOME:-}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"
   do
      [ -n "${candidate}" ] || continue
      case "${candidate}" in
         '/make-helper-one.bsh' )
            continue
            ;;
      esac
      if test -r "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! helper_file="$(locate_helper)"; then
   printf '%s\n' 'FATAL: make-helper-one.bsh not found (set GENMKFILE_SHARE).' >&2
   exit 1
fi

## Capability gate: this suite tests the genmkfile CHECKOUT (wired via GENMKFILE_BIN or
## GENMKFILE_SHARE). If nothing was wired and only the installed /usr/share/genmkfile helper
## resolved -- which drifts from the tree under review -- SKIP rather than report a confusing
## FAIL against a possibly-stale subject nobody is changing.
if [ -z "${GENMKFILE_SHARE:-}" ] && [ -z "${GENMKFILE_BIN:-}" ] \
   && [ "${helper_file}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
if ! type -P grep-dctrl >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: grep-dctrl (dctrl-tools) is required.' >&2
   exit 1
fi
if ! type -P dpkg-architecture >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: dpkg-architecture (dpkg-dev) is required.' >&2
   exit 1
fi

## Source the REAL file; sourcing does not run the was_executed-guarded main, so only the
## function definitions load. GENMKFILE_PATH so any runtime source inside the file resolves.
GENMKFILE_PATH="$(dirname -- "${helper_file}")"
export GENMKFILE_PATH
## style-ok: allow-sc1091-disable -- helper_file is located at runtime, unfollowable
# shellcheck disable=SC1090,SC1091
source "${helper_file}"

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

tests_total=0
tests_failed=0

pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }

## --- make_dependencies_filter_helper (flat, no alternative-parsing) ---
## The flat filter keeps BOTH names of an 'A | B' alternative on purpose (a real
## first-alternative choice needs a Debian-dep parser). These canary the leaks it MUST NOT
## have: a space-less 'A|B' must not collapse to 'AB'; build-profile '<...>' and any '${...}'
## substvar must be stripped. Compare on whitespace-collapsed output (the real consumer
## word-splits it unquoted anyway).
check_filter() {
   local desc="$1" input="$2" want="$3" got
   ## Collapse runs of whitespace to one space and trim, so spacing is not asserted.
   got="$(printf '%s' "${input}" | make_dependencies_filter_helper | tr -s '[:space:]' ' ')"
   got="${got# }"
   got="${got% }"
   tests_total=$(( tests_total + 1 ))
   if [ "${got}" = "${want}" ]; then
      pass "${desc} -> '${got}'"
   else
      fail "${desc}: want '${want}' got '${got}'"
   fi
}

check_filter 'space-less alternative does not collapse' 'foo|bar' 'foo bar'
check_filter 'spaced alternative keeps both'            'default-mta | mail-transport-agent' 'default-mta mail-transport-agent'
check_filter 'build-profile restriction stripped'       'foo <!nocheck>, bar' 'foo bar'
check_filter 'any substvar stripped'                    '${perl:Depends}, python3' 'python3'
check_filter 'version + arch qualifiers stripped'       'debhelper (>= 13), pkg [linux-any]' 'debhelper pkg'

## --- the stanza-parse loop maps Package/Architecture to the expected .deb list ---
## Package and Architecture are simple, single-line Debian fields (not folded), so a multi-arch
## list is on ONE line. Target arm64 is covered by 'amd64 arm64 armhf', 'all' is arch-independent,
## and an arch-excluded stanza yields no .deb but is still recorded in make_package_list so
## deb-cleanup/reprepro can handle any stale copy.
cat > "${test_root}/control" <<'EOF'
Source: testsrc

Package: multiarchpkg
Architecture: amd64 arm64 armhf

Package: allpkg
Architecture: all

Package: otherarchpkg
Architecture: amd64
EOF
make_debian_control_file_absolute_path="${test_root}/control"
make_source_package_name='testsrc'
make_pkg_version='1.0'
make_pkg_revision='-1'
target_architecture='arm64'
DISTDIR="${test_root}/dist"
make_cross_build_platform_list='arm64'
make_package_debs_files_list=()
make_package_list=()
all_target_debs_are_arch_all='true'
make_get_variables_parse_stanzas

tests_total=$(( tests_total + 1 ))
want_deb="${DISTDIR}/multiarchpkg_1.0-1_arm64.deb"
found='false'
for d in "${make_package_debs_files_list[@]}"; do
   [ "${d}" = "${want_deb}" ] && found='true'
done
if [ "${found}" = 'true' ]; then
   pass 'single-line multi-arch Architecture covers the target (arm64 .deb expected)'
else
   fail "multi-arch not covered -> ${want_deb} not in [${make_package_debs_files_list[*]}]"
fi

tests_total=$(( tests_total + 1 ))
want_all="${DISTDIR}/allpkg_1.0-1_all.deb"
found='false'
for d in "${make_package_debs_files_list[@]}"; do
   [ "${d}" = "${want_all}" ] && found='true'
done
if [ "${found}" = 'true' ]; then
   pass "'Architecture: all' is arch-independent (all .deb expected)"
else
   fail "'all' not arch-independent -> ${want_all} not in [${make_package_debs_files_list[*]}]"
fi

tests_total=$(( tests_total + 1 ))
excluded='true'
for d in "${make_package_debs_files_list[@]}"; do
   case "${d}" in *otherarchpkg*) excluded='false' ;; esac
done
in_list='false'
for p in "${make_package_list[@]}"; do
   [ "${p}" = 'otherarchpkg' ] && in_list='true'
done
if [ "${excluded}" = 'true' ] && [ "${in_list}" = 'true' ]; then
   pass 'an arch-excluded stanza yields no .deb but stays in make_package_list'
else
   fail "arch-excluded handling wrong: excluded=${excluded} in_list=${in_list} debs=[${make_package_debs_files_list[*]}]"
fi

## --- a malformed debian/control must ABORT, not silently drop packages ---
## grep-dctrl exits non-zero and emits only the stanzas parsed so far on a syntax error; the parser
## must fail loud, not read the truncated output and drop the rest. Override exit_with_error (its
## make_output_error path needs colour/trace state only a full run sets up) with a recording stub.
# shellcheck disable=SC2317  # invoked indirectly via make_get_variables_parse_stanzas
exit_with_error() { printf 'DIE: %s\n' "$2" >&2; exit 66; }
cat > "${test_root}/control-bad" <<'EOF'
Source: badsrc

Package: valid1
Architecture: all

Invalid-Line-Without-Colon

Package: valid2
Architecture: any
EOF
make_debian_control_file_absolute_path="${test_root}/control-bad"
make_source_package_name='badsrc'
target_architecture='amd64'
make_package_debs_files_list=()
make_package_list=()
all_target_debs_are_arch_all='true'
tests_total=$(( tests_total + 1 ))
bad_rc=0
( make_get_variables_parse_stanzas ) >/dev/null 2>&1 || bad_rc=$?
if [ "${bad_rc}" -ne 0 ]; then
   pass 'a malformed debian/control aborts the parser (no silent package drop)'
else
   fail "malformed control did not abort: rc=${bad_rc} list=[${make_package_debs_files_list[*]}]"
fi

## --- a path-traversal 'Package:' name from debian/control must be REJECTED ---
## The parsed name is later interpolated into safe-rm --recursive -- "debian/${package}" and
## DISTDIR deletion globs; an unvalidated name could delete outside the tree. The parser must
## reject a name containing '/' OR starting with '.' (mirrors the '#pkgname' guard). Assert the
## SPECIFIC name guard fired -- exit 66 (the override below) AND its message -- not just some
## abort, and cover BOTH branches independently (a '/'-only name that is NOT dot-prefixed, and a
## bare '..'), so a validator that checked only one branch would still fail here.
assert_pkg_rejected() {
   local bad_name="$1" desc="$2" out rc=0
   cat > "${test_root}/control-badname" <<EOF
Source: bnsrc

Package: good-one
Architecture: all

Package: ${bad_name}
Architecture: all
EOF
   make_debian_control_file_absolute_path="${test_root}/control-badname"
   make_source_package_name='bnsrc'
   target_architecture='amd64'
   make_package_debs_files_list=()
   make_package_list=()
   all_target_debs_are_arch_all='true'
   out="$( ( make_get_variables_parse_stanzas ) 2>&1 )" || rc=$?
   tests_total=$(( tests_total + 1 ))
   if [ "${rc}" -eq 66 ] && [[ "${out}" == *'invalid binary package name'* ]]; then
      pass "${desc} rejected by the name guard (exit 66 + message)"
   else
      fail "${desc} NOT rejected by the name guard: rc=${rc} out=[${out}]"
   fi
}
assert_pkg_rejected 'legit/../../victim' "a '/'-bearing traversal name (not dot-prefixed)"
assert_pkg_rejected '..' "a bare '..' name"

## The validation must NOT over-reject: an interior '.' (even consecutive) is a valid Debian
## package name and cannot form a traversal without a '/'. Guards against a too-broad pattern.
cat > "${test_root}/control-dots" <<'EOF'
Source: dotsrc

Package: lib.foo..bar
Architecture: all
EOF
make_debian_control_file_absolute_path="${test_root}/control-dots"
make_source_package_name='dotsrc'
target_architecture='amd64'
make_package_debs_files_list=()
make_package_list=()
all_target_debs_are_arch_all='true'
dots_rc=0
( make_get_variables_parse_stanzas ) >/dev/null 2>&1 || dots_rc=$?
tests_total=$(( tests_total + 1 ))
if [ "${dots_rc}" -eq 0 ]; then
   pass 'a valid interior-dot package name (lib.foo..bar) is accepted'
else
   fail "a valid interior-dot package name was wrongly rejected: rc=${dots_rc}"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "dependency_and_arch_parse_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "dependency_and_arch_parse_test: ${tests_total} pass, 0 fail, 0 skip"
