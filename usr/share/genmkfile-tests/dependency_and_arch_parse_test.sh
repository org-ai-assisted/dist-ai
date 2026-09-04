#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make-helper-one.bsh debian/control parsing:
##  - make_dependencies_filter_helper (flat, no alternative-parsing): must not collapse a
##    space-less 'A|B' to 'AB', and must strip build-profile '<...>' and any '${...}' substvar.
##  - parse_control_package_stanzas' Package/Architecture loop must capture RFC822 FOLDED
##    continuation lines (a multi-line 'Architecture: amd64\n arm64', and a folded '\n all'),
##    or a covered target reads as uncovered and its .deb vanishes from the expected list.
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

## --- folded Architecture in the stanza-parse loop ---
## Drive the REAL parse_control_package_stanzas against a control whose Architecture field is
## folded across lines. Target arm64 is covered only via a continuation line.
cat > "${test_root}/control" <<'EOF'
Source: testsrc

Package: foldedpkg
Architecture: amd64
 arm64
 armhf

Package: allpkg
Architecture: all

Package: foldedall
Architecture:
 all
EOF

## Globals the parser reads/writes (set as the caller make_get_variables would).
make_debian_control_file_absolute_path="${test_root}/control"
make_source_package_name='testsrc'
make_pkg_version='1.0'
make_pkg_revision='-1'
target_architecture='arm64'
DISTDIR="${test_root}/dist"
make_package_debs_files_list=()
make_package_list=()
all_package_debs_are_arch_all='true'

parse_control_package_stanzas

tests_total=$(( tests_total + 1 ))
want_deb="${DISTDIR}/foldedpkg_1.0-1_arm64.deb"
found='false'
for d in "${make_package_debs_files_list[@]}"; do
   [ "${d}" = "${want_deb}" ] && found='true'
done
if [ "${found}" = 'true' ]; then
   pass "folded Architecture: arm64 continuation covers target -> foldedpkg arm64 .deb expected"
else
   fail "folded Architecture: arm64 dropped -> ${want_deb} not in [${make_package_debs_files_list[*]}]"
fi

## grok #3: 'Architecture:' empty on the header line, 'all' on a continuation line. The value
## arrives as ' all' (leading space); it must still be recognised as arch-independent.
tests_total=$(( tests_total + 1 ))
want_all="${DISTDIR}/foldedall_1.0-1_all.deb"
found='false'
for d in "${make_package_debs_files_list[@]}"; do
   [ "${d}" = "${want_all}" ] && found='true'
done
if [ "${found}" = 'true' ]; then
   pass "folded Architecture: 'all' on a continuation line -> foldedall _all .deb expected"
else
   fail "folded 'Architecture: <newline> all' not arch-independent -> ${want_all} not in [${make_package_debs_files_list[*]}]"
fi

## --- folded 'Package:' continuation must normalise away the leading blank ---
## grep-dctrl emits a folded 'Package:' as 'Package: ' (empty value) + an indented continuation,
## so 'Package:\n foldedname' reaches the loop as ' foldedname'. 'Architecture:' is normalised at
## the stanza boundary but 'Package:' was NOT, leaving a leading blank that corrupts the expected
## .deb name ('.../ foldedname_..._all.deb' -> test -f false-negative -> false build failure) and
## the make_package_list entry ('debian/ foldedname' -> deb-clean/deb-cleanup miss the real dir).
cat > "${test_root}/control-pkgfold" <<'EOF'
Source: pkgfoldsrc

Package:
 foldedname
Architecture: all
EOF
make_debian_control_file_absolute_path="${test_root}/control-pkgfold"
make_source_package_name='pkgfoldsrc'
target_architecture='amd64'
make_package_debs_files_list=()
make_package_list=()
all_package_debs_are_arch_all='true'
parse_control_package_stanzas

tests_total=$(( tests_total + 1 ))
if [ "${#make_package_list[@]}" -eq 1 ] && [ "${make_package_list[0]}" = 'foldedname' ]; then
   pass "folded 'Package:' continuation normalised -> 'foldedname' (no leading blank)"
else
   fail "folded 'Package:' not normalised -> make_package_list=[${make_package_list[*]}]"
fi

tests_total=$(( tests_total + 1 ))
want_pkgfold="${DISTDIR}/foldedname_1.0-1_all.deb"
found='false'
for d in "${make_package_debs_files_list[@]}"; do
   [ "${d}" = "${want_pkgfold}" ] && found='true'
done
if [ "${found}" = 'true' ]; then
   pass "folded 'Package:' -> correctly-named .deb (no leading blank)"
else
   fail "folded 'Package:' .deb misnamed -> ${want_pkgfold} not in [${make_package_debs_files_list[*]}]"
fi

## --- architecture wildcard 'any-<cpu>' + env-arch independence (dpkg-architecture -f -a) ---
## 'any-arm' covers armhf (whose CPU is 'arm', not 'armhf'); a hand-rolled matcher missed it and
## dropped the covered .deb. ALSO pin DEB_HOST_ARCH=amd64 in the env (a cross-build / post-
## dpkg-buildpackage state): dpkg-architecture ignores '-a' when DEB_HOST_ARCH is set unless '-f'
## is given, so the match must honor the TARGET (armhf), not the env arch. wildpkg's armhf .deb
## must be expected.
cat > "${test_root}/control-wild" <<'EOF'
Source: wildsrc

Package: wildpkg
Architecture: any-arm
EOF
make_debian_control_file_absolute_path="${test_root}/control-wild"
make_source_package_name='wildsrc'
target_architecture='armhf'
make_package_debs_files_list=()
make_package_list=()
all_package_debs_are_arch_all='true'
export DEB_HOST_ARCH=amd64
parse_control_package_stanzas
unset DEB_HOST_ARCH
tests_total=$(( tests_total + 1 ))
want_wild="${DISTDIR}/wildpkg_1.0-1_armhf.deb"
found='false'
for d in "${make_package_debs_files_list[@]}"; do
   [ "${d}" = "${want_wild}" ] && found='true'
done
if [ "${found}" = 'true' ]; then
   pass "arch wildcard 'any-arm' covers target armhf (dpkg-architecture matching)"
else
   fail "arch wildcard 'any-arm' did not cover armhf -> ${want_wild} not in [${make_package_debs_files_list[*]}]"
fi

## --- a malformed debian/control must ABORT, not silently drop packages ---
## grep-dctrl exits non-zero and emits only the stanzas parsed so far on a syntax error; the parser
## must fail loud, not read the truncated output and drop the rest. Override exit_with_error (its
## make_output_error path needs colour/trace state only a full run sets up) with a recording stub.
# shellcheck disable=SC2317  # invoked indirectly via parse_control_package_stanzas
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
all_package_debs_are_arch_all='true'
tests_total=$(( tests_total + 1 ))
bad_rc=0
( parse_control_package_stanzas ) >/dev/null 2>&1 || bad_rc=$?
if [ "${bad_rc}" -ne 0 ]; then
   pass 'a malformed debian/control aborts the parser (no silent package drop)'
else
   fail "malformed control did not abort: rc=${bad_rc} list=[${make_package_debs_files_list[*]}]"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "dependency_and_arch_parse_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "dependency_and_arch_parse_test: ${tests_total} pass, 0 fail, 0 skip"
