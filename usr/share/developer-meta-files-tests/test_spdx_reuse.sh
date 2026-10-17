#!/bin/bash

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@kicksecure.com>
## SPDX-License-Identifier: AGPL-3.0-or-later

## AI-Assisted

## Behavioural test for developer-meta-files' spdx-reuse.bsh (the SPDX/REUSE
## hybrid converter). Sources the real library and drives the real functions.
## Unit-asserts the pure converters (email-domain derivation; per-line header
## rewrite for every comment-prefix variant; year drop; non-company holder
## preserved), then runs spdx_reuse_convert_tree end-to-end over a git fixture
## and asserts: existing headers rewritten to SPDX; headers ADDED to
## comment-capable files that lacked one; a verbatim COPYING left untouched (its
## AGPL 'Copyright (C) <year>' sample must NOT be rewritten); debian/copyright
## DEP-5 years dropped + company email normalized while its indented license text
## stays verbatim; a NARROW REUSE.toml generated (precedence = "closest", the
## generic globs, the leftover data file, and NO 'path = "**"'); and finally
## 'reuse lint' exits 0.
##
## Self-contained; sources the side-effect-free library. reuse + git are real
## requirements. Needs no root, no network, no build.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Scrub inherited git location vars: GIT_DIR OVERRIDES 'git -C', so a caller with
## GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE set (a git hook, 'git submodule foreach')
## would make the fixture's git ops -- and the sourced convert_tree's 'git ls-files'
## -- operate on the CALLER's repo instead. Unset them before any git runs.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}
assert_eq() {
   ## assert_eq <want> <got> <desc>
   if [ "$1" = "$2" ]; then
      pass "$3"
   else
      fail "$3 (want '$1', got '$2')"
   fi
}
assert_grep() {
   ## assert_grep <file> <fixed-string> <desc>
   if grep --quiet --fixed-strings -- "$2" "$1"; then
      pass "$3"
   else
      fail "$3"
   fi
}
assert_not_grep() {
   ## assert_not_grep <file> <fixed-string> <desc>
   if grep --quiet --fixed-strings -- "$2" "$1"; then
      fail "$3"
   else
      pass "$3"
   fi
}

rel='usr/libexec/developer-meta-files/spdx-reuse.bsh'
candidates=()
[ -z "${SPDX_REUSE_BSH:-}" ] || candidates+=( "${SPDX_REUSE_BSH}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: spdx-reuse.bsh not found (set SPDX_REUSE_BSH)." >&2
   exit 1
fi
for tool in reuse git safe-rm; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; a hard requirement of the test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090 # path resolved at runtime
source "${subject}"

K='adrelanos@kicksecure.com'
W='adrelanos@whonix.org'

## --- UNIT: email domain derived from the package path -----------------------
assert_eq "${K}" "$(spdx_reuse_email_for_path /x/packages/kicksecure/sdwdate)" \
   "email: packages/kicksecure -> kicksecure.com"
assert_eq "${W}" "$(spdx_reuse_email_for_path /x/packages/whonix/anon-meta)" \
   "email: packages/whonix -> whonix.org"
assert_eq "${K}" "$(spdx_reuse_email_for_path /x/anything-else)" \
   "email: default -> kicksecure.com"

## --- UNIT: per-line conversion, every comment-prefix variant ----------------
assert_eq "## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "$(spdx_reuse_convert_line '## Copyright (C) 2022 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>' "${K}")" \
   "convert: '## ' company copyright -> SPDX (years dropped, email normalized)"
assert_eq "# SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "$(spdx_reuse_convert_line '# Copyright (C) 2017 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>' "${K}")" \
   "convert: '# ' company copyright -> SPDX"
assert_eq "SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "$(spdx_reuse_convert_line 'Copyright (C) 2016 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>' "${K}")" \
   "convert: bare company copyright -> SPDX (C block / HTML comment)"
assert_eq "## SPDX-License-Identifier: AGPL-3.0-or-later" \
   "$(spdx_reuse_convert_line '## See the file COPYING for copying conditions.' "${K}")" \
   "convert: '## ' conditions line -> SPDX-License-Identifier"
assert_eq "# SPDX-License-Identifier: AGPL-3.0-or-later" \
   "$(spdx_reuse_convert_line '# See the file COPYING for copying conditions.' "${K}")" \
   "convert: '# ' conditions line -> SPDX-License-Identifier"
assert_eq "SPDX-License-Identifier: AGPL-3.0-or-later" \
   "$(spdx_reuse_convert_line 'See the file COPYING for copying conditions.' "${K}")" \
   "convert: bare conditions line -> SPDX-License-Identifier"
assert_eq "## SPDX-FileCopyrightText: troubadour <trobador@riseup.net>" \
   "$(spdx_reuse_convert_line '## Copyright (C) 2015 troubadour <trobador@riseup.net>' "${K}")" \
   "convert: non-company holder preserved (year dropped, email NOT normalized)"
## CANARY: a line that matches no marker must pass through byte-identical, so the
## converter is proven to rewrite only what it recognizes (not blindly).
canary_in='readonly foo="Copyright notice in a string"'
assert_eq "${canary_in}" "$(spdx_reuse_convert_line "${canary_in}" "${K}")" \
   "canary: a non-header line is returned unchanged"

## --- INTEGRATION: convert a git fixture tree end to end ---------------------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

fixture="${workdir}/pkg"
mkdir --parents -- "${fixture}/usr/bin" "${fixture}/usr/lib" "${fixture}/src" \
   "${fixture}/man" "${fixture}/translations" "${fixture}/LICENSES" "${fixture}/debian"

## Legacy header lines, assembled from variables so the literal does not appear
## as a source header line (which the gate's R-002 would misread as THIS file's
## own header). The written fixtures are byte-identical to real Kicksecure files.
co='Copyright (C)'
cond='See the file COPYING for copying conditions.'

## Files carrying the legacy header, one per comment-prefix variant.
cat > "${fixture}/usr/bin/toolscript" <<EOF
#!/bin/bash

## ${co} 2022 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## ${cond}

true
EOF
cat > "${fixture}/usr/lib/mod.py" <<EOF
#!/usr/bin/python3 -su

# ${co} 2017 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# ${cond}

x = 1
EOF
cat > "${fixture}/src/thing.c" <<EOF
/*
${co} 2016 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
${cond}
*/

int main(void) { return 0; }
EOF
cat > "${fixture}/man/thing.8.ronn" <<EOF
thing(8) -- a thing
====================

<!--
# ${co} 2012 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# ${cond}
-->

## SYNOPSIS
EOF
cat > "${fixture}/AGENTS.md" <<EOF
<!--
${co} 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
${cond}
-->

# Agents
EOF
## Multiple holders: a non-company holder above the company line.
cat > "${fixture}/translations/x.yaml" <<EOF
## ${co} 2015 troubadour <trobador@riseup.net>
## ${co} 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## ${cond}

key: value
EOF

## Comment-capable files WITHOUT a header (headers get added).
cat > "${fixture}/README.md" <<'EOF'
# readme

text
EOF
cat > "${fixture}/Makefile" <<'EOF'
all:
	true
EOF
cat > "${fixture}/.gitignore" <<'EOF'
*.tmp
EOF

## Uncommentable data file (ends up in REUSE.toml's leftover list).
cat > "${fixture}/config-test.txt" <<'EOF'
0.pool.example
1.pool.example
EOF

## Verbatim COPYING: its AGPL 'Copyright (C) <year> <name of author>' sample must
## NOT be rewritten by the converter.
cat > "${fixture}/COPYING" <<'EOF'
GNU AFFERO GENERAL PUBLIC LICENSE
Version 3, 19 November 2007

    Copyright (C) <year>  <name of author>
EOF
## LICENSES text present, so convert_tree does not attempt a network download.
cat > "${fixture}/LICENSES/AGPL-3.0-or-later.txt" <<'EOF'
GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (verbatim text placeholder).
EOF

cat > "${fixture}/debian/control" <<'EOF'
Source: testpkg
Maintainer: Test <test@example.com>

Package: testpkg
Architecture: all
Description: fixture
 Fixture.
EOF
## DEP-5: the field must lose its years + normalize the company email; the
## indented license-text sample below it must stay verbatim.
cat > "${fixture}/debian/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2012 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
License: AGPL-3+

License: AGPL-3+
 On Debian systems see /usr/share/common-licenses/AGPL-3.
 .
    Copyright (C) <year>  <name of author>
EOF

## An old star-glob REUSE.toml that must be REPLACED by the narrow one.
cat > "${fixture}/REUSE.toml" <<'EOF'
version = 1

[[annotations]]
path = "**"
precedence = "aggregate"
SPDX-FileCopyrightText = "2012 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>"
SPDX-License-Identifier = "AGPL-3.0-or-later"
EOF

## A git checkout is required (convert_tree enumerates via 'git ls-files').
## Hooks disabled persistently (not just -c on one call): the fixture is not
## testing the operator's git hooks, and convert_tree runs its own git.
git -C "${fixture}" -c init.defaultBranch=main init --quiet
git -C "${fixture}" config core.hooksPath /dev/null
git -C "${fixture}" add --all

## Pre-state canaries: the fixture starts WITHOUT SPDX and WITH the old layout.
if grep --quiet --recursive --fixed-strings --exclude-dir=.git -- 'SPDX-FileCopyrightText:' "${fixture}"; then
   fail "canary: fixture already has SPDX headers before conversion"
else
   pass "canary: fixture has no SPDX headers before conversion"
fi
if grep --quiet --fixed-strings -- 'path = "**"' "${fixture}/REUSE.toml"; then
   pass "canary: fixture starts with the old star-glob REUSE.toml"
else
   fail "canary: fixture should start with the old star-glob REUSE.toml"
fi

## Run the real converter. convert_tree returns 'reuse lint's exit status.
lint_log="${workdir}/lint.log"
lint_rc=0
spdx_reuse_convert_tree "${fixture}" > "${lint_log}" 2>&1 || lint_rc="$?"

## Each converted file carries the expected SPDX lines (prefix preserved).
assert_grep "${fixture}/usr/bin/toolscript" "## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "toolscript: '## ' SPDX header"
assert_grep "${fixture}/usr/lib/mod.py" "# SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "mod.py: '# ' SPDX header"
assert_grep "${fixture}/src/thing.c" "SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "thing.c: bare SPDX header in C block"
assert_grep "${fixture}/man/thing.8.ronn" "# SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "thing.8.ronn: '# ' SPDX header in HTML comment"
assert_grep "${fixture}/translations/x.yaml" "SPDX-FileCopyrightText: troubadour <trobador@riseup.net>" \
   "x.yaml: non-company holder preserved"

## Legacy headers must be REPLACED, not merely supplemented: the unique conditions
## phrase must survive NOWHERE (it is absent from COPYING and the DEP-5 license
## text, so a tree-wide check is exact). Presence by output, not grep's exit code.
leftover="$(grep --recursive --fixed-strings --exclude-dir=.git \
   -- 'See the file COPYING for copying conditions.' "${fixture}" || true)"
if [ -n "${leftover}" ]; then
   fail "a legacy conditions line survived (header appended, not replaced): ${leftover}"
else
   pass "no legacy conditions line survives (headers replaced in place)"
fi

## Years must be gone from EVERY copyright: the per-file ':' SPDX form, the
## REUSE.toml ' = ' SPDX form, AND debian/copyright's DEP-5 'Copyright:' field.
## Matched by OUTPUT presence (a grep error exits non-zero but prints nothing, so
## the old 'if grep' form would mis-read an error as 'no year').
year_hits="$(grep --recursive --extended-regexp --exclude-dir=.git \
   -- 'SPDX-FileCopyrightText.*[0-9][0-9][0-9][0-9]' "${fixture}" || true)"
dep5_year="$(grep --extended-regexp -- '^Copyright:.*[0-9][0-9][0-9][0-9]' \
   "${fixture}/debian/copyright" || true)"
if [ -n "${year_hits}${dep5_year}" ]; then
   fail "a converted copyright still carries a year: ${year_hits}${dep5_year}"
else
   pass "no converted copyright (SPDX header, REUSE.toml, or DEP-5) carries a year"
fi

## Headers ADDED to comment-capable files that lacked one.
assert_grep "${fixture}/README.md" 'SPDX-FileCopyrightText:' "README.md: SPDX header added (HTML)"
## The added HTML header must OPEN on line 1 and be closed ('-->' is a
## printf-format footgun, hence this guard; order-sensitive, not two loose greps).
if [ "$(head -n 1 -- "${fixture}/README.md")" = '<!--' ] \
   && grep --quiet --fixed-strings -- '-->' "${fixture}/README.md"; then
   pass "README.md: HTML header opens on line 1 and is closed"
else
   fail "README.md: added HTML header not well-formed (line 1 '<!--' + a later '-->')"
fi
assert_grep "${fixture}/Makefile" '## SPDX-FileCopyrightText:' "Makefile: SPDX header added (hash)"
assert_grep "${fixture}/.gitignore" '## SPDX-FileCopyrightText:' ".gitignore: SPDX header added (hash)"

## COPYING must be untouched (its AGPL sample line is NOT an SPDX header).
assert_grep "${fixture}/COPYING" 'Copyright (C) <year>  <name of author>' \
   "COPYING: AGPL sample line left verbatim"
assert_not_grep "${fixture}/COPYING" 'SPDX-' "COPYING: no SPDX tag injected"

## debian/copyright: DEP-5 field year-dropped + email normalized; license text verbatim.
assert_grep "${fixture}/debian/copyright" "Copyright: ENCRYPTED SUPPORT LLC <${K}>" \
   "debian/copyright: DEP-5 field years dropped + email normalized"
assert_grep "${fixture}/debian/copyright" 'Copyright (C) <year>  <name of author>' \
   "debian/copyright: indented license sample stays verbatim"

## REUSE.toml: narrow, precedence=closest, generic globs + the leftover data file,
## and the old star-glob gone.
## The blanket '**' must be gone in ANY spelling (scalar 'path = "**"' or a list
## 'path = ["**"]'), so reject the '"**"' token itself, not one fixed spelling.
if grep --quiet --fixed-strings -- 'precedence = "closest"' "${fixture}/REUSE.toml" \
   && grep --quiet --fixed-strings -- '"debian/**"' "${fixture}/REUSE.toml" \
   && grep --quiet --fixed-strings -- '"config-test.txt"' "${fixture}/REUSE.toml" \
   && ! grep --quiet --fixed-strings -- '"**"' "${fixture}/REUSE.toml"; then
   pass "REUSE.toml: narrow precedence=closest, generic globs + leftover, no '**' glob"
else
   fail "REUSE.toml: not the expected narrow hybrid shape"
fi

## reuse lint must pass on the converted tree (convert_tree's own returned rc).
if [ "${lint_rc}" -eq 0 ]; then
   pass "reuse lint exits 0 on the converted tree"
else
   fail "reuse lint failed (rc=${lint_rc}):"
   cat -- "${lint_log}" >&2
fi

## Re-run reuse lint INDEPENDENTLY (do not solely trust the subject's returned rc:
## a convert_tree that wrote headers but skipped reuse lint and returned 0 would
## otherwise pass vacuously).
indep_lint_rc=0
( cd -- "${fixture}" && reuse lint ) > "${workdir}/indep-lint.log" 2>&1 || indep_lint_rc="$?"
if [ "${indep_lint_rc}" -eq 0 ]; then
   pass "independent reuse lint exits 0 on the converted tree"
else
   fail "independent reuse lint failed (rc=${indep_lint_rc}):"
   cat -- "${workdir}/indep-lint.log" >&2
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: spdx-reuse.bsh hybrid conversion verified (${pass_count} assertions)."
