#!/bin/bash

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@kicksecure.com>
## SPDX-License-Identifier: AGPL-3.0-or-later

## AI-Assisted

## Behavioural test for developer-meta-files' spdx-reuse.bsh (the SPDX/REUSE
## hybrid converter). Sources the real library and drives the real functions.
## Unit-asserts the pure converters (email-domain derivation; per-line header
## rewrite for every comment-prefix variant; year drop; non-company holder
## preserved), then runs spdx_reuse_convert_tree end-to-end over a git fixture
## and asserts: existing headers rewritten to SPDX; comment-capable files that
## lack a header are REPORTED (not injected -- the tool never writes a comment
## prefix, so it cannot corrupt a polkit .rules = JS / fontconfig .conf = XML) and
## left unchanged; a verbatim COPYING left untouched (its AGPL 'Copyright (C)
## <year>' sample must NOT be rewritten); debian/copyright DEP-5 years dropped +
## company email normalized while its indented license text stays verbatim; a
## NARROW REUSE.toml generated (precedence = "closest", the generic globs, the
## leftover data file, and NO 'path = "**"'); and finally 'reuse lint' is RED
## until a human adds the reported headers (the intended "point out" end-state).
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
for tool in reuse git safe-rm str_replace; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; a hard requirement of the test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090 # path resolved at runtime
source "${subject}"

K='adrelanos@kicksecure.com'
W='adrelanos@whonix.org'

## Legacy header markers, assembled from variables so a literal header line does not
## appear in this test's own source (the gate's R-002 would misread it as THIS file's
## header). Fixtures built from them are byte-identical to real Kicksecure files.
co='Copyright (C)'
cond='See the file COPYING for copying conditions.'

## --- UNIT: email domain derived from the package path -----------------------
assert_eq "${K}" "$(spdx_reuse_email_for_path /x/packages/kicksecure/sdwdate)" \
   "email: packages/kicksecure -> kicksecure.com"
assert_eq "${W}" "$(spdx_reuse_email_for_path /x/packages/whonix/anon-meta)" \
   "email: packages/whonix -> whonix.org"
assert_eq "${K}" "$(spdx_reuse_email_for_path /x/anything-else)" \
   "email: default -> kicksecure.com"

## --- UNIT: convert_file rewrites headers in place via literal str_replace -----
## Drive the REAL convert_file on a one-line temp file. Proves the str_replace path:
## the company year is dropped + email normalized, the comment prefix and any
## SAME-LINE closer (/* */, <!-- -->) are preserved (finding 1), and a non-company
## holder keeps its year + handle (the year drop is anchored on the company name).
convert_one() {
   ## convert_one <line> <email> ; echoes the converted single line
   local line="$1" email="$2" tmp
   tmp="$(mktemp)"
   printf '%s\n' "${line}" > "${tmp}"
   spdx_reuse_convert_file "${tmp}" "${email}"
   cat -- "${tmp}"
   safe-rm --force -- "${tmp}"
}
assert_eq "## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "$(convert_one "## ${co} 2022 - 2025 ENCRYPTED SUPPORT LLC <${W}>" "${K}")" \
   "convert: '## ' company header -> SPDX (year dropped, email normalized)"
assert_eq "# SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "$(convert_one "# ${co} 2017 - 2025 ENCRYPTED SUPPORT LLC <${W}>" "${K}")" \
   "convert: '# ' company header -> SPDX"
assert_eq "## SPDX-License-Identifier: AGPL-3.0-or-later" \
   "$(convert_one "## ${cond}" "${K}")" \
   "convert: '## ' conditions -> SPDX-License-Identifier"
## FINDING 1: a SINGLE-LINE block / HTML header keeps its closer (pre-fix the closer
## was dropped, leaving an unterminated comment that swallowed the rest of the file).
assert_eq "<!-- ## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}> -->" \
   "$(convert_one "<!-- ## ${co} 2019 - 2025 ENCRYPTED SUPPORT LLC <${W}> -->" "${K}")" \
   "convert: single-line <!-- --> company header keeps its closer"
assert_eq "<!-- ## SPDX-License-Identifier: AGPL-3.0-or-later -->" \
   "$(convert_one "<!-- ## ${cond} -->" "${K}")" \
   "convert: single-line <!-- --> conditions keeps its closer"
assert_eq "/* SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}> */" \
   "$(convert_one "/* ${co} 2020 - 2025 ENCRYPTED SUPPORT LLC <${W}> */" "${K}")" \
   "convert: single-line /* */ company header keeps its closer"
## A multi-line block whose CLOSER rides the conditions line keeps the ' */' too
## (the real .c/.js header shape), so the comment never swallows the code below.
assert_eq "   SPDX-License-Identifier: AGPL-3.0-or-later */" \
   "$(convert_one "   ${cond} */" "${K}")" \
   "convert: conditions line carrying the block closer keeps ' */'"
## Company off-domain email (riseup.net) folded into the package domain.
assert_eq "## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>" \
   "$(convert_one "## ${co} 2013 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@riseup.net>" "${K}")" \
   "convert: company riseup.net email normalized to the package domain"
## Non-company holder: year KEPT, handle + email untouched (company-anchored drop).
assert_eq "## SPDX-FileCopyrightText: 2015 troubadour <trobador@riseup.net>" \
   "$(convert_one "## ${co} 2015 troubadour <trobador@riseup.net>" "${K}")" \
   "convert: non-company holder keeps its year and handle"

## --- INTEGRATION: convert a git fixture tree end to end ---------------------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

fixture="${workdir}/pkg"
mkdir --parents -- "${fixture}/usr/bin" "${fixture}/usr/lib" "${fixture}/src" \
   "${fixture}/man" "${fixture}/translations" "${fixture}/LICENSES" "${fixture}/debian" \
   "${fixture}/usr/libexec/developer-meta-files"

## co / cond are defined above (reused for the fixture headers). The written
## fixtures are byte-identical to real Kicksecure files.

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

## Comment-capable files WITHOUT a header: the tool REPORTS them (missing SPDX
## header) and leaves them unchanged; a human adds the real per-file header.
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
## An EXTENSIONLESS file whose first line is a shebang is comment-capable: with no
## legacy header it is REPORTED as missing (not injected), left verbatim.
cat > "${fixture}/usr/bin/helperscript" <<'EOF'
#!/bin/bash
echo hi
EOF
## The converter's OWN source carries the marker + email literals as CODE (the
## has-header grep, the str_replace arguments). It already ships an SPDX header, so
## pass 2 / REUSE.toml leave it alone; pass 1 must SKIP it by path, else the
## whole-file str_replace rewrites its own logic. Built from co/cond so the literal
## header line does not appear in THIS test's source.
cat > "${fixture}/usr/libexec/developer-meta-files/spdx-reuse.bsh" <<EOF
#!/bin/bash

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <${K}>
## SPDX-License-Identifier: AGPL-3.0-or-later

grep --quiet -F -- '${cond}' "\${1}"
str_replace "${co} " 'SPDX-FileCopyrightText: ' "\${1}"
str_replace 'adrelanos@whonix.org' "\${2}" "\${1}"
EOF

## Uncommentable data file (ends up in REUSE.toml's leftover list).
cat > "${fixture}/config-test.txt" <<'EOF'
0.pool.example
1.pool.example
EOF

## Header-incapable extensions: no comment syntax (json) and a compiled binary
## catalog (mo). A human CANNOT add a per-file header, so they must be swept into
## REUSE.toml like other data, NOT nagged as missing-header. Classified by
## extension, so the body content is immaterial.
cat > "${fixture}/config.json" <<'EOF'
{ "key": "value" }
EOF
cat > "${fixture}/translations/messages.mo" <<'EOF'
compiled gettext catalog placeholder
EOF

## Verbatim COPYING: its AGPL 'Copyright (C) <year> <name of author>' sample must
## NOT be rewritten by the converter.
cat > "${fixture}/COPYING" <<'EOF'
GNU AFFERO GENERAL PUBLIC LICENSE
Version 3, 19 November 2007

    Copyright (C) <year>  <name of author>
EOF
## A generated changelog that QUOTES the legacy header in a commit message. pass 1
## must SKIP it (like pass 2 / REUSE.toml already do), or the whole-file str_replace
## rewrites the recorded commit text + the historical maintainer email.
cat > "${fixture}/changelog.upstream" <<EOF
testpkg (1.0-1) unstable; urgency=medium

  * Dropped the legacy header '## ${co} 2012 - 2025 ENCRYPTED SUPPORT LLC <${W}>'
    and '## ${cond}' in favor of SPDX tags.

 -- test <test@example.com>  Thu, 01 Jan 2026 00:00:00 +0000
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

## A JS file with a shebang and NO header: comment-capable, so REPORTED as missing
## and left verbatim (polkit/fontconfig are exactly why the tool no longer guesses
## a comment syntax to inject).
cat > "${fixture}/tool.js" <<'EOF'
#!/usr/bin/env node
console.log("hi");
EOF

## A tracked symlink pointing OUTSIDE the repo, whose target carries a legacy
## header: conversion must NOT follow the link and rewrite the external file.
external_target="${workdir}/external-target.sh"
cat > "${external_target}" <<EOF
#!/bin/bash

## ${co} 2019 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## ${cond}

true
EOF
ln -s -- "${external_target}" "${fixture}/link.sh"

## A git checkout is required (convert_tree enumerates via 'git ls-files').
## Hooks disabled persistently (not just -c on one call): the fixture is not
## testing the operator's git hooks, and convert_tree runs its own git.
git -C "${fixture}" -c init.defaultBranch=main init --quiet
git -C "${fixture}" config core.hooksPath /dev/null
git -C "${fixture}" add --all

## Pre-state canaries: the fixture starts WITHOUT SPDX and WITH the old layout.
## Exclude spdx-reuse.bsh: it ships an SPDX header on purpose (the converter skips it).
if grep --quiet --recursive --fixed-strings --exclude-dir=.git --exclude='spdx-reuse.bsh' -- 'SPDX-FileCopyrightText:' "${fixture}"; then
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
## Non-company holder keeps its handle, email, AND its year (the year drop is
## anchored on the company name, so a contributor's copyright is left intact).
assert_grep "${fixture}/translations/x.yaml" "SPDX-FileCopyrightText: 2015 troubadour <trobador@riseup.net>" \
   "x.yaml: non-company holder preserved, year kept"

## Legacy headers must be REPLACED, not merely supplemented: the unique conditions
## phrase must survive NOWHERE (absent from COPYING and the DEP-5 license text).
## Exclude spdx-reuse.bsh and changelog.upstream: both carry the phrase as CODE /
## quoted text and are SKIPPED by the converter on purpose (see the skip assertions
## below). Presence by output.
leftover="$(grep --recursive --fixed-strings --exclude-dir=.git \
   --exclude='spdx-reuse.bsh' --exclude='changelog.upstream' \
   -- 'See the file COPYING for copying conditions.' "${fixture}" || true)"
if [ -n "${leftover}" ]; then
   fail "a legacy conditions line survived (header appended, not replaced): ${leftover}"
else
   pass "no legacy conditions line survives (headers replaced in place)"
fi

## The converter SKIPS its own source (operator-chosen guard): the code literals in
## spdx-reuse.bsh must survive verbatim -- NOT rewritten to SPDX -- so running the
## converter over the developer-meta-files package cannot mangle its own logic.
self="${fixture}/usr/libexec/developer-meta-files/spdx-reuse.bsh"
assert_grep "${self}" 'See the file COPYING for copying conditions.' \
   "skip: converter's own has-header grep literal left intact"
assert_grep "${self}" "${co} " \
   "skip: converter's own copyright-marker str_replace argument left intact"
assert_grep "${self}" 'adrelanos@whonix.org' \
   "skip: converter's own email str_replace argument left intact"
## changelog.upstream is skipped too: its quoted header + historical maintainer
## email must survive verbatim (not rewritten into SPDX tags / the package domain).
assert_grep "${fixture}/changelog.upstream" 'See the file COPYING for copying conditions.' \
   "skip: changelog.upstream quoted conditions line left intact"
assert_grep "${fixture}/changelog.upstream" 'adrelanos@whonix.org' \
   "skip: changelog.upstream historical maintainer email left intact"

## COMPANY (ENCRYPTED SUPPORT LLC) copyrights must lose their year in the per-file
## ':' SPDX header and the REUSE.toml ' = ' SPDX form; a non-company contributor's
## year is intentionally KEPT, so this is scoped to the company holder. The year may
## sit before OR after the holder, so match both orders. The DEP-5 'Copyright:' field
## is dropped for every single holder (fix_dep5's behaviour), so check it unscoped.
## Matched by OUTPUT presence (a grep error prints nothing; the old 'if grep' form
## would mis-read an error as 'no year').
year_hits="$(grep --recursive --extended-regexp --exclude-dir=.git \
   -- 'SPDX-FileCopyrightText.*([0-9]{4}.*ENCRYPTED SUPPORT LLC|ENCRYPTED SUPPORT LLC.*[0-9]{4})' \
   "${fixture}" || true)"
dep5_year="$(grep --extended-regexp -- '^Copyright:.*[0-9][0-9][0-9][0-9]' \
   "${fixture}/debian/copyright" || true)"
if [ -n "${year_hits}${dep5_year}" ]; then
   fail "a converted copyright still carries a year (company SPDX/REUSE.toml or DEP-5): ${year_hits}${dep5_year}"
else
   pass "no converted company SPDX/REUSE.toml copyright, nor the DEP-5 field, carries a year"
fi

## Comment-capable files that lacked a header are REPORTED (printed by the
## converter), NOT injected. The tool never writes a comment prefix into a file
## (guessing a comment SYNTAX per extension is what would corrupt a polkit
## .rules = JavaScript or fontconfig .conf = XML), so a human adds the real
## per-file header. The report lands in convert_tree's captured output.
for missing in README.md Makefile .gitignore tool.js usr/bin/helperscript; do
   if grep --quiet --fixed-strings -- "SPDX header MISSING (add one manually): ${missing}" "${lint_log}"; then
      pass "reported missing header: ${missing}"
   else
      fail "missing-header file not reported: ${missing}"
   fi
done
## ... and each is left UNCHANGED: no injected header, content/shebang verbatim.
for untouched in README.md Makefile .gitignore tool.js usr/bin/helperscript; do
   if grep --quiet --fixed-strings -- 'SPDX-FileCopyrightText:' "${fixture}/${untouched}"; then
      fail "a header was injected into ${untouched} (the tool must only report, not mutate)"
   else
      pass "left unmutated (no injected header): ${untouched}"
   fi
done
## Shebang scripts untouched (line 1 intact -- the files were not rewritten).
if [ "$(head -n 1 -- "${fixture}/tool.js")" = '#!/usr/bin/env node' ] \
   && [ "$(head -n 1 -- "${fixture}/usr/bin/helperscript")" = '#!/bin/bash' ]; then
   pass "shebang scripts left verbatim (tool.js, helperscript)"
else
   fail "a shebang script was modified (the tool must only report, not mutate)"
fi

## A tracked symlink is NEVER written through: its external target (carrying a
## legacy header) must be left verbatim, and the link must still be a symlink.
assert_grep "${external_target}" 'See the file COPYING for copying conditions.' \
   "symlink target OUTSIDE the repo not followed/rewritten"
if [ -L "${fixture}/link.sh" ]; then
   pass "link.sh: still a symlink (not replaced by a regular file)"
else
   fail "link.sh: converted in place (should have been skipped)"
fi

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

## Header-incapable extensions (json, mo) are uncommentable DATA: swept into
## REUSE.toml, NOT nagged as missing-header (nothing a human could add to them).
assert_not_grep "${lint_log}" "SPDX header MISSING (add one manually): config.json" \
   "config.json: header-incapable, not nagged"
assert_grep "${fixture}/REUSE.toml" '"config.json"' \
   "config.json: swept into REUSE.toml"
assert_not_grep "${lint_log}" "SPDX header MISSING (add one manually): translations/messages.mo" \
   "messages.mo: header-incapable, not nagged"
assert_grep "${fixture}/REUSE.toml" '"translations/messages.mo"' \
   "messages.mo: swept into REUSE.toml"

## reuse lint is RED on the converted tree by design: the reported comment-capable
## files still lack a per-file header (the tool points them out; a human adds
## them, it never injects). That red IS the "point out" end-state, not a
## regression. convert_tree returns reuse lint's rc.
if [ "${lint_rc}" -ne 0 ]; then
   pass "reuse lint is red until the reported headers are added (convert_tree rc)"
else
   fail "reuse lint unexpectedly passed -- the reported missing-header files must fail it:"
   cat -- "${lint_log}" >&2
fi

## Re-run reuse lint INDEPENDENTLY (do not solely trust the subject's returned rc:
## a convert_tree that silently skipped reuse lint and returned non-zero would
## otherwise pass vacuously). It must flag the reported files for a human to fix.
indep_lint_rc=0
( cd -- "${fixture}" && reuse lint ) > "${workdir}/indep-lint.log" 2>&1 || indep_lint_rc="$?"
if [ "${indep_lint_rc}" -ne 0 ]; then
   pass "independent reuse lint is red (reported files lack a per-file header)"
else
   fail "independent reuse lint unexpectedly passed (reported files should fail it):"
   cat -- "${workdir}/indep-lint.log" >&2
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: spdx-reuse.bsh hybrid conversion verified (${pass_count} assertions)."
