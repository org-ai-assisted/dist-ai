#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make-helper-one.bsh debian/control parsing:
##  - make_dependencies_filter_helper (flat, no alternative-parsing): must not collapse a
##    space-less 'A|B' to 'AB', and must strip build-profile '<...>' and any '${...}' substvar.
##  - make_get_variables' Package/Architecture stanza loop must capture RFC822 FOLDED
##    continuation lines (a multi-line 'Architecture: amd64\n arm64', and a folded '\n all'),
##    or a covered target reads as uncovered and its .deb vanishes from the expected list.

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
sed -n '/^make_dependencies_filter_helper()/,/^}/p' -- "${helper_file}" \
   > "${test_root}/filter.sh"
# shellcheck disable=SC1091
source "${test_root}/filter.sh"

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
## Drive the REAL loop (extracted between its sentinels) against a control whose Architecture
## field is folded across lines. Target arm64 is covered only via a continuation line.
sed -n '/^make_architecture_covers_target()/,/^}/p' -- "${helper_file}" \
   > "${test_root}/arch.sh"
sed -n '/GENMKFILE-TEST-EXTRACT: stanza-parse-loop BEGIN/,/GENMKFILE-TEST-EXTRACT: stanza-parse-loop END/p' \
   -- "${helper_file}" > "${test_root}/loop.sh"
if ! test -s "${test_root}/loop.sh" || ! grep --quiet 'while IFS= read -r line' "${test_root}/loop.sh"; then
   printf '%s\n' "ERROR: could not extract the stanza-parse loop (sentinels moved?)." >&2
   exit 1
fi

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

# shellcheck disable=SC1091
source "${test_root}/arch.sh"

## Globals the extracted loop reads/writes.
make_debian_control_file_absolute_path="${test_root}/control"
make_source_package_name='testsrc'
make_pkg_version='1.0'
make_pkg_revision='-1'
target_architecture='arm64'
DISTDIR="${test_root}/dist"
make_package_debs_files_list=()
make_package_list=()
all_package_debs_are_arch_all='true'
package=''
binary_package_architecture=''
current_field=''
line=''
temp=''
skip_debs_artifact=''
package_name_architecture=''

# shellcheck disable=SC1091
source "${test_root}/loop.sh"

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

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "dependency_and_arch_parse_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "dependency_and_arch_parse_test: ${tests_total} pass, 0 fail, 0 skip"
