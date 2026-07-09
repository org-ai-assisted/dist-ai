#!/bin/bash
## Comprehensive adversarial suite for git-meld. Drives a REAL 'git diff' with
## git-meld as diff.external and asserts each adversarial change class is
## SURFACED (never hidden). Also checks the 'git meld' re-dispatch pre-flight
## surfaces files git skips (binary/.gitattributes). Safe payloads; meld stubbed.
## $1 = git-meld under test.
## style-ok: no-safe-rm (rm only touches throwaway mktemp workspaces)
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

GIT_MELD="$(readlink -f -- "${1:?usage: adv-final.sh /path/to/git-meld}")"
work="$(mktemp -d)"; export HOME="${work}/home"; mkdir -p "${HOME}"
git config --global user.email t@example.com; git config --global user.name test
git config --global init.defaultBranch master; git config --global protocol.file.allow always
mkdir -p "${work}/bin"; meld_log="${work}/display.log"
for gui in meld kdiff3; do
   { printf "%s\n" "#!/bin/bash"; printf "printf \"DISPLAY:%%s\\n\" \"$*\">>\"%s\"\n" "${meld_log}"; } >"${work}/bin/${gui}"
   chmod +x "${work}/bin/${gui}"
done
export PATH="${work}/bin:${PATH}"

fails=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; fails=$((fails+1)); }

## review <name> <expected-regex> : diff HEAD~1..HEAD through git-meld as driver;
## PASS if git-meld output OR a meld invocation matches the expected signal.
review () {
   local name expect out
   name="$1"; expect="$2"
   true >"${meld_log}"
   out="$( git -c "diff.external=${GIT_MELD}" diff HEAD~1 HEAD 2>&1 || true )$(cat "${meld_log}")"
   if printf '%s' "${out}" | grep -qiE "${expect}"; then pass "${name}"
   else fail "${name} (no '${expect}'); saw: $(printf '%s' "${out}"|tr '\n' '|'|cut -c1-120)"; fi
}

## Fresh single-file-change repo each time, so nothing bleeds between cases.
new_repo () { rm -rf "${work}/r"; git init -q "${work}/r"; cd "${work}/r"
   printf '#!/bin/sh\necho hi\n' >a.sh; printf 'plain\n' >b.txt; git add -A; git commit -qm base; }

printf '== git-meld adversarial suite: %s ==\n' "${GIT_MELD}"

new_repo; chmod +x a.sh; git add -A; git commit -qm x
review "mode-only-+x"                 'MODE CHANGE|EXECUTABLE|old mode|new mode'

new_repo; printf '#!/bin/sh\nEVIL\n' >a.sh; git add -A; git commit -qm x
review "content-change (control)"     'DISPLAY:|@@|EVIL'

## Regression: a plain changed file must NOT report a false "stcat failed".
## git-diff-review once reused the 'diff' rc-1 ("files differ") for the stcat
## exit-code check, so every changed file mis-reported an stcat failure and
## dumped a redundant unicode-show report. meld/kdiff3 never touch stcat, so
## this holds for them trivially.
new_repo; printf '#!/bin/sh\necho changed\n' >a.sh; git add -A; git commit -qm x
true >"${meld_log}"
nofalse_out="$( git -c "diff.external=${GIT_MELD}" diff HEAD~1 HEAD 2>&1 || true )"
if printf '%s' "${nofalse_out}" | grep -qi 'stcat failed'; then
   fail "false 'stcat failed' reported for a plain changed file"
else
   pass "no false 'stcat failed' for a plain changed file"
fi

new_repo; printf 'Subproject commit 0123456789abcdef0123456789abcdef01234567\n' >b.txt; git add -A; git commit -qm x
review "fake-Subproject content spoof" 'mimics a gitlink|DISPLAY:'

new_repo; rm b.txt; ln -s /etc/passwd b.txt; git add -A; git commit -qm x
review "file->symlink swap"           'SYMLINK|mode 12|symbolic'

new_repo; rm b.txt; ln -s "1000 108 127 997 1000printf 'tgt\xe2\x80\xae')" b.txt; git add -A; git commit -qm x
review "symlink target bidi unicode"   'unicode-show|SYMLINK'

## Regression: a symlink RETARGET (both sides symlinks) must show the actual old
## and new targets, not empty. In external-diff mode git hands a regular temp
## file whose CONTENT is the target path; read_target once ran 'readlink' on
## that (keyed on core.symlinks), which failed and rendered the target empty,
## hiding the retarget from the reviewer.
## core.symlinks=true is the case that broke: the old readlink-on-a-temp-file
## path only fires when git thinks symlinks are supported.
new_repo; git config core.symlinks true; rm b.txt; ln -s /old-symlink-target b.txt; git add -A; git commit -qm sl1
rm b.txt; ln -s /new-symlink-target b.txt; git add -A; git commit -qm sl2
retarget_out="$( git -c "diff.external=${GIT_MELD}" diff HEAD~1 HEAD 2>&1 || true )"
if printf '%s' "${retarget_out}" | grep -q '/old-symlink-target' \
   && printf '%s' "${retarget_out}" | grep -q '/new-symlink-target'; then
   pass "symlink retarget shows old and new targets (not empty)"
else
   fail "symlink retarget targets hidden; saw: $(printf '%s' "${retarget_out}"|tr '\n' '|'|cut -c1-160)"
fi

new_repo; printf '#!/bin/sh\nif x # \xe2\x80\xae\xe2\x81\xa6then evil\xe2\x81\xa9\n' >b.txt; git add -A; git commit -qm x
review "trojan-source bidi unicode"   'unicode-show'

## Undecodable (non-UTF-8, unicode-show rc 2) content must FAIL CLOSED: surfaced,
## but the viewer is NEVER opened (guards the driver's pre-open fatal gate).
new_repo
printf 'x\xff y\n' >b.txt
git add -A
git commit -qm x
true >"${meld_log}"
fatal_out="$( git -c "diff.external=${GIT_MELD}" diff HEAD~1 HEAD 2>&1 || true )"
if printf '%s' "${fatal_out}" | grep -qiE 'undecodable|non-UTF-8' && ! grep -q 'DISPLAY:' "${meld_log}"; then
   pass "undecodable content fails closed (viewer never opened)"
else
   fail "undecodable content NOT fail-closed (meld_log: $(tr '\n' '|' < "${meld_log}"))"
fi

## Even under GIT_REVIEW_UNICODE_NONFATAL, a GUI viewer (git-meld/git-kdiff3) must
## STILL fail closed on a fatal blob -- only the terminal-safe git-diff-review may
## defer. GIT_MELD does not set git_review_display_terminal_safe, so the viewer
## must never open here regardless of NONFATAL.
true >"${meld_log}"
GIT_REVIEW_UNICODE_NONFATAL=1 git -c "diff.external=${GIT_MELD}" diff HEAD~1 HEAD >/dev/null 2>&1 || true
if ! grep -q 'DISPLAY:' "${meld_log}"; then
   pass "undecodable + NONFATAL still fails closed for a GUI viewer"
else
   fail "undecodable + NONFATAL OPENED the GUI viewer (meld_log: $(tr '\n' '|' < "${meld_log}"))"
fi

new_repo; printf 'x\n' >c.txt; git add -A; git commit -qm x
review "added file"                   'DISPLAY:|new file|@@'

## Real submodule gitlink change.
new_repo
sm="${work}/sm"; git init -q "${sm}"; ( cd "${sm}"; printf '1\n'>f; git add -A; git commit -qm s1; printf '2\n'>f; git add -A; git commit -qm s2 )
git -c protocol.file.allow=always submodule add -q "${sm}" mod 2>/dev/null; git commit -qm addmod
( cd mod; git checkout -q HEAD~1 ); git add mod; git commit -qm 'bump submodule'
## The driver prints the path %q-quoted inside literal single quotes:
## "Submodule 'mod': ...". Match with or without the quotes.
review "submodule gitlink change"     "Submodule '?mod'?:"

## A submodule's own file content is untrusted; a dangerous terminal escape in it
## must be neutralized (stcat) in the inner diff, never passed raw to the terminal.
new_repo
sme="${work}/sme"
git init -q "${sme}"
( cd "${sme}"; git config user.email t@example.com; git config user.name test; printf '1\n' >g; git add -A; git commit -qm a; printf 'evil\x1b]0;PWNED\x07here\n' >g; git add -A; git commit -qm b )
git -c protocol.file.allow=always submodule add -q "${sme}" smod 2>/dev/null
git commit -qm addsmod
( cd smod; git checkout -q HEAD~1 )
git add smod
git commit -qm 'bump smod'
esc_out="$( git -c "diff.external=${GIT_MELD}" diff HEAD~1 HEAD 2>&1 || true )"
if printf '%s' "${esc_out}" | grep -q "$( printf '\x1b')"; then
   fail "submodule inner diff leaked a raw terminal escape"
else
   pass "submodule inner diff neutralizes terminal escapes (stcat)"
fi

## Pre-flight: a .gitattributes-binary-suppressed change must still be listed by
## the re-dispatch overview even though git skips the per-file driver.
new_repo
printf 'a.sh binary\n' >.gitattributes; git add -A; git commit -qm attr
printf '#!/bin/sh\nrm -rf /\n' >a.sh; git add -A; git commit -qm evilbinary
true >"${meld_log}"
preflight="$( "${GIT_MELD}" HEAD~1 HEAD 2>&1 || true )"
if printf '%s' "${preflight}" | grep -qE 'change set|diffstat' && printf '%s' "${preflight}" | grep -qE 'a\.sh'; then
   pass "driver-skipped (binary) file listed in pre-flight"
else
   fail "binary-suppressed a.sh not surfaced in pre-flight; saw: $(printf '%s' "${preflight}"|tr '\n' '|'|cut -c1-160)"
fi

printf '\n==== FAILURES: %s ====\n' "${fails}"
rm -rf "${work}"; exit "${fails}"
