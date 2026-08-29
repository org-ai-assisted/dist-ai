#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Engine hardening regressions, driven through the shell harness (so the suite
## runner picks them up) against the REAL dist_ai package:
##   * a '## style-ok:' waiver on a CRLF line is honored (fail-closed regression)
##   * the fixer's write refuses a symlink swapped in AFTER the scan (TOCTOU)

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## Prefer the in-tree package (usr/share/<suite>/ -> usr/lib/...), else installed.
LIB="${tool_test_dir}/../../lib/python3/dist-packages"
if [ ! -d "${LIB}/dist_ai" ]; then
   LIB='/usr/lib/python3/dist-packages'
fi
export PYTHONPATH="${LIB}${PYTHONPATH:+:${PYTHONPATH}}"

for prereq in python3 safe-rm shellcheck; do
   type -P "${prereq}" >/dev/null 2>&1 || {
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   }
done

test_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${test_dir}"; }
trap cleanup EXIT

passc=0
fail=0
note_pass() { printf '%s\n' "PASS: ${1}"; passc=$(( passc + 1 )); }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2; fail=$(( fail + 1 )); }

## --- CRLF-terminated style-ok waiver is honored ------------------------------
## Canary: the old '(?:[ \t]|$)' boundary matched '$' before '\n' (i.e. AFTER
## the '\r'), so a CRLF waiver with no space after the tag was dropped and the
## rule fired fail-closed. A real '\r' in the boundary fixes it.
crlf_waiver="$(python3 -c '
from dist_ai import context
src = "#!/bin/bash\r\n## style-ok: allow-non-ascii\r\nx = 1\r\n"
print(context.FileContext("f.sh", src).has_waiver("allow-non-ascii"))
')"
if [ "${crlf_waiver}" = "True" ]; then
   note_pass "CRLF-terminated style-ok waiver is honored"
else
   note_fail "CRLF-terminated style-ok waiver dropped (got '${crlf_waiver}')"
fi

## --- fixer TOCTOU: a symlink swapped in after the scan is not followed --------
## from_disk refuses a symlink when the context is BUILT; apply_fixes must refuse
## to write through one that replaces the path afterwards. Canary: a plain open()
## followed the symlink and overwrote an arbitrary victim file.
victim="${test_dir}/victim.txt"
target="${test_dir}/target.sh"
printf '%s\n' 'VICTIM ORIGINAL' > "${victim}"
## A fixable file (trailing whitespace) so apply_fixes actually wants to write.
printf '%s\n' '#!/bin/bash' 'true   ' > "${target}"
toctou="$(python3 -c '
import os, sys
from dist_ai import context, engine
target, victim = sys.argv[1], sys.argv[2]
ctx = context.FileContext.from_disk(target)     ## built against the regular file
os.remove(target); os.symlink(victim, target)   ## swap in a symlink to the victim
engine.apply_fixes(ctx, check=False)            ## must NOT write through it
with open(victim) as handle:
    print(handle.read().strip())
' "${target}" "${victim}")"
if [ "${toctou}" = "VICTIM ORIGINAL" ]; then
   note_pass "fixer write refuses a symlink swapped in after the scan"
else
   note_fail "fixer followed a swapped-in symlink and clobbered the victim (got '${toctou}')"
fi

## --- staged-blob shellcheck honors the project .shellcheckrc -----------------
## A virtual (staged) context materializes to a temp file; shellcheck discovers
## '.shellcheckrc' by walking up from the CHECKED file's dir, so a temp-dir blob
## dropped the project rc and the gate failed a file that is clean IN PLACE.
## Canary: the rc disables SC2016 and the content triggers ONLY SC2016, so a
## shellcheck finding here means the rc was not applied to the blob (the bug).
rcdir="${test_dir}/proj"
mkdir --parents -- "${rcdir}"
printf '%s\n' 'disable=SC2016' > "${rcdir}/.shellcheckrc"
sc_rc="$(python3 -c '
import sys
from dist_ai import context, engine, model
abspath = sys.argv[1]
## disk_backed=False -> a VIRTUAL (staged) context: materialized() writes the
## bytes to a temp file; abspath only supplies the real source dir + rc location.
ctx = context.FileContext("proj/f.sh", "#!/bin/bash\necho \x27$x\x27\n",
                          abspath=abspath, disk_backed=False)
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
' "${rcdir}/f.sh")"
if [ "${sc_rc}" = "0" ]; then
   note_pass "staged-blob shellcheck honors the project .shellcheckrc"
else
   note_fail "staged-blob shellcheck ignored .shellcheckrc (got ${sc_rc} SC2016 finding(s))"
fi

## --- staged-blob shellcheck reads .shellcheckrc from the BLOB'S TREE ----------
## In --staged/--range mode the file is a committed/staged BLOB, so its
## '.shellcheckrc' must come from the blob's OWN git tree (source_rev), NEVER the
## working tree -- else a dirty/unstaged 'disable=...' would suppress a real
## finding in the object that SHIPS (the dirty-rc bypass). Canary: commit a shell
## file with SC2016 and NO rc in the tree, then leave a DIRTY worktree
## .shellcheckrc disabling SC2016; the staged blob (source_rev='') must STILL
## report SC2016 (the dirty rc is ignored). FAILS pre-fix (the worktree rc, read
## from the on-disk dir, suppresses it).
sc_blob="$(python3 -c '
import sys, os, subprocess
from dist_ai import context, engine, model
D = os.path.join(sys.argv[1], "blobtree")
os.makedirs(D)
def git(*a): subprocess.run(["git", "-C", D] + list(a), check=True, capture_output=True)
git("init", "--quiet"); git("config", "user.email", "t@e.st"); git("config", "user.name", "t")
open(D + "/prog.sh", "w").write("#!/bin/bash\necho \x27$x\x27\n")   # SC2016
git("add", "prog.sh"); git("commit", "--quiet", "-m", "init")
open(D + "/.shellcheckrc", "w").write("disable=SC2016\n")           # DIRTY, unstaged, not in the tree
## source_rev="" -> the INDEX (a staged blob); the rc must come from the tree.
ctx = context.FileContext("prog.sh", open(D + "/prog.sh").read(),
                          abspath=D + "/prog.sh", source_rev="")
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
' "${test_dir}")"
if [ "${sc_blob}" != "0" ]; then
   note_pass "staged-blob shellcheck reads .shellcheckrc from the blob tree, not the dirty worktree"
else
   note_fail "staged-blob shellcheck applied the DIRTY worktree .shellcheckrc (dirty-rc bypass)"
fi

## --- staged-blob shellcheck rc lookup resists a git object-spec collision ------
## A blob path PREFIX is attacker-controlled: a PR that names a directory '0:pwn'
## made the walk-up rc lookup 'git show :0:pwn/.shellcheckrc', which git MISPARSES
## as ':<stage 0>:pwn/.shellcheckrc' -- reading a DIFFERENT, attacker-planted rc to
## SUPPRESS shellcheck on the PR's own scripts. Canary: stage a failing script under
## '0:pwn/' AND a 'disable=all' rc at 'pwn/.shellcheckrc' (the misparse target) but
## NONE in the real '0:pwn/' tree. A SHA-keyed whole-tree lookup finds no governing
## rc there, so SC2016 STILL fires. FAILS pre-fix (the misparse reads pwn/.shellcheckrc
## and the finding is suppressed -> a real shellcheck bypass on a malicious PR).
sc_collide="$(python3 -c '
import sys, os, subprocess
from dist_ai import context, engine, model
D = os.path.join(sys.argv[1], "collide")
os.makedirs(os.path.join(D, "0:pwn"))
os.makedirs(os.path.join(D, "pwn"))
def git(*a): subprocess.run(["git", "-C", D] + list(a), check=True, capture_output=True)
git("init", "--quiet"); git("config", "user.email", "t@e.st"); git("config", "user.name", "t")
open(D + "/0:pwn/prog.sh", "w").write("#!/bin/bash\necho \x27$x\x27\n")   # SC2016
open(D + "/pwn/.shellcheckrc", "w").write("disable=all\n")               # the misparse target
git("add", "-A"); git("commit", "--quiet", "-m", "init")
ctx = context.FileContext("0:pwn/prog.sh", open(D + "/0:pwn/prog.sh").read(),
                          abspath=D + "/0:pwn/prog.sh", source_rev="")
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
' "${test_dir}")"
if [ "${sc_collide}" != "0" ]; then
   note_pass "staged-blob shellcheck rc lookup resists a git object-spec collision (0:dir)"
else
   note_fail "staged-blob shellcheck rc: a '0:dir' object-spec collision SUPPRESSED the finding (bypass)"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-engine-hardening: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-engine-hardening: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
