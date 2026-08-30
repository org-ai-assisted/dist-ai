#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Two debian/control parsing bugs in make-helper-one.bsh:
##  1. make_dependencies_filter_helper turned an ALTERNATIVE group 'A | B' into hard
##     requirements on BOTH (it stripped '|' as a substring), so 'apt-get install' demanded
##     mutually-exclusive alternatives and failed. Fix: keep only the first alternative.
##  2. the Package/Architecture stanza loop dropped RFC822 FOLDED continuation lines (a
##     multi-line 'Architecture: amd64\n arm64'), so a covered target read as uncovered and
##     its expected .deb vanished from make_package_debs_files_list. Fix: append continuations.

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

## --- Bug 1: make_dependencies_filter_helper ---
sed -n '/^make_dependencies_filter_helper()/,/^}/p' -- "${helper_file}" \
   > "${test_root}/filter.sh"
# shellcheck disable=SC1091
source "${test_root}/filter.sh"

check_filter() {
   local desc="$1" input="$2" want="$3" got
   got="$(printf '%s' "${input}" | make_dependencies_filter_helper)"
   tests_total=$(( tests_total + 1 ))
   if [ "${got}" = "${want}" ]; then
      pass "${desc} -> '${got}'"
   else
      fail "${desc}: want '${want}' got '${got}'"
   fi
}

check_filter 'alternative group keeps first only' \
   'default-mta | mail-transport-agent, foo (>= 1.0)' 'default-mta foo'
check_filter 'plain versioned deps' \
   'debhelper (>= 13), debhelper-compat (= 13)' 'debhelper debhelper-compat'
check_filter 'substitution markers dropped' \
   '${misc:Depends}, python3' 'python3'
check_filter 'folded (newline) continuation' \
   "$(printf 'a,\n b (>= 1)')" 'a b'
check_filter 'arch qualifier stripped + alt group' \
   'pkg [linux-any], x | y | z' 'pkg x'

## --- Bug 2: folded Architecture in the stanza-parse loop ---
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

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "dependency_and_arch_parse_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "dependency_and_arch_parse_test: ${tests_total} pass, 0 fail, 0 skip"
