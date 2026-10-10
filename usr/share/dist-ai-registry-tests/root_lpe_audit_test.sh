#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-root-lpe-audit: the LPE detector layered on dm-root-scripts-enum is driven
## over a fixture root-script TREE (controlled input for the enumerator +
## detector, like the sibling root_scripts_enum_test.sh drives the enum). The
## fixture plants ONE vuln per rule class AND a SAFE counterpart per class, so a
## pass proves BOTH directions: the planted vulns are detected (no silent miss)
## and the safe cases stay clean (no false green from over-flagging). It also
## pins the reachability engine: a cross-submodule unit->ExecStart target, a
## self-gated root script found by no reference, and a genmkfile '#pkg' suffix.
## The REAL tool is driven from the checkout; per-finding assertions live in the
## standalone checker beside it. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v DIST_AI_REPO ] || DIST_AI_REPO=""

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-tests-all" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -x "${repo}/usr/bin/dm-root-lpe-audit" ]; then
   printf '%s\n' 'FATAL: dist-ai-registry-tests: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

subject="${repo}/usr/bin/dm-root-lpe-audit"
checker="${script_dir}/root_lpe_audit_check.py"

if [ ! -f "${checker}" ]; then
   printf '%s\n' "FATAL: missing assertion checker '${checker}'." >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/root-lpe-audit-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

write() {
   ## write <relative-path> ; body on stdin
   local rel dir
   rel="$1"
   dir="$(dirname -- "${work_dir}/${rel}")"
   mkdir --parents -- "${dir}"
   cat > "${work_dir}/${rel}"
}

## --- fixture: a miniature derivative-maker tree -----------------------------

## Two submodules so a unit in one resolves to an ExecStart target in the other.
write '.gitmodules' <<'EOF'
[submodule "unitpkg"]
	path = packages/kicksecure/unitpkg
	url = https://example.invalid/unitpkg.git
[submodule "targetpkg"]
	path = packages/kicksecure/targetpkg
	url = https://example.invalid/targetpkg.git
EOF

## Root boot unit; its ExecStart lives in a DIFFERENT submodule (cross-submodule
## reachability, weight HIGH = boot).
write 'packages/kicksecure/unitpkg/usr/lib/systemd/system/vuln-boot.service' <<'EOF'
[Unit]
Description=planted boot vuln
[Service]
Type=oneshot
ExecStart=/usr/libexec/targetpkg/vuln-boot
[Install]
WantedBy=multi-user.target
EOF

## VULN: root recursive cp/chown into a user home at boot -> HIGH via boot unit.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-boot' <<'EOF'
#!/bin/bash
user_name="user"
home_dir="/home/${user_name}"
cp --archive --recursive /etc/skel/. "${home_dir}"
chown --recursive "${user_name}:${user_name}" "${home_dir}/.config"
EOF

## VULN: a self-gated root helper referenced by NOTHING in-tree (root-guarded
## reachability), shipped with a genmkfile '#pkg' suffix. One planted vuln per
## remaining rule class.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-guarded#targetpkg-shared' <<'EOF'
#!/bin/bash
root_check() {
   if [ "$(id -u)" != "0" ]; then
      echo "ERROR: must be run as root!"
      exit 1
   fi
}
root_check
target_user="$1"
home_folder="/home/${target_user}"
find "${home_folder}" -name '*.tmp' -delete
cp --dereference /etc/skel/.bashrc "${home_folder}/.bashrc"
chmod 777 "${home_folder}/pub"
: > /dev/shm/vuln-guarded.lock
PATH=.:${PATH}
. "${home_folder}/hooks/pre.sh"
EOF

## VULN: a maintainer script trusting $SUDO_USER unvalidated (trust-sudo-user +
## recursive home write), weight HIGH = every install.
write 'packages/kicksecure/targetpkg/debian/postinst' <<'EOF'
#!/bin/bash
set -e
target="/home/${SUDO_USER}"
chown --recursive "${SUDO_USER}:${SUDO_USER}" "${target}/.ssh"
EOF

## SAFE boot unit + target: mktemp temp, root:root, absolute non-home, safe mode.
write 'packages/kicksecure/unitpkg/usr/lib/systemd/system/safe-boot.service' <<'EOF'
[Unit]
Description=safe boot
[Service]
Type=oneshot
ExecStart=/usr/libexec/targetpkg/safe-boot
[Install]
WantedBy=multi-user.target
EOF

write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/safe-boot' <<'EOF'
#!/bin/bash
tmp="$(mktemp --directory)"
cp --recursive /usr/share/skel/. "${tmp}/"
chown --recursive root:root /var/lib/targetpkg
install -m 0755 /usr/share/targetpkg/x /usr/local/bin/x
chmod --recursive ugo-w /var/lib/targetpkg/images
EOF

## VULN: exercises the AST-precision classes an earlier version missed --
## a 'command'/'env' wrapper in front of the sink, a path-valued option
## (--target-directory), a 'declare' assignment feeding taint, and a find whose
## tainted token is a -name PATTERN (NOT the walk root, must not false-fire).
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-wrappers' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
target_user="$1"
command chown --recursive root:root "/home/${target_user}/wrapdir"
cp --recursive --target-directory="/home/${target_user}/tdir" /etc/skel/a
declare decldir="/home/${target_user}/.ssh"
chmod --recursive 777 "${decldir}"
find /var/log -name "${target_user}.log"
EOF

## VULN: the round-2 AST-precision classes -- a wrapper option that takes a
## VALUE (nice -n), find GLOBAL options before the path (-L), dd's of= write
## target, and a symbolic world-write with '=' (a=w).
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-round2' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
nice -n 10 chown --recursive root:root "/home/${tu}/wrap"
find -L "/home/${tu}/logs" -delete
dd if=/etc/shadow of="/home/${tu}/shadow"
chmod a=w "/home/${tu}/pub"
EOF

## VULN: GNU 'env' reads NAME=VALUE operands AFTER '--' ('env -- A=1 cmd' runs
## cmd), so the wrapper peeler must NOT stop skipping at '--' for env -- it has
## to keep consuming leading assignments and resolve the REAL command. A peeler
## that breaks on '--' resolves the command to the assignment word and MISSES the
## sink (silent green). Single assignment after '--'.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-env-single' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env -- LPE=1 chown --recursive root:root "/home/${tu}/single"
EOF

## VULN: multiple assignments after '--' exercise the consume LOOP, not a single
## skip ('env -- A=1 B=2 cmd' still runs cmd).
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-env-multi' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env -- A=1 B=2 chown --recursive root:root "/home/${tu}/multi"
EOF

## VULN: GNU env puts NO identifier constraint on a NAME=VALUE operand -- it
## treats ANY word containing '=' as an assignment ('X-Y=1', '0=1', '--unset=P'
## all set a variable), so a peeler that only skips shell-identifier names peels
## to the assignment word and misses the sink.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-env-nonid' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env -- X-Y=1 chown --recursive root:root "/home/${tu}/nonid"
EOF

## VULN: a QUOTED/EXPANDED assignment ('"PATH=$PATH"') has no static word_string,
## so the '=' operand test must read the RAW word, not a parsed literal.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-env-expand' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env -- "PATH=$PATH" chown --recursive root:root "/home/${tu}/expand"
EOF

## VULN: a lone '-' right after options is 'env --ignore-environment' (GNU synopsis
## 'env [OPTION]... [-] [NAME=VALUE]... [COMMAND]'), NOT the command -- assignments
## still follow it, so the peeler must consume it and keep looking for the command.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-env-dash' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env -- - PATH=/usr/bin chown --recursive root:root "/home/${tu}/dash"
EOF

## SAFE: '--' only ends option parsing while getopt is still running; a NAME=VALUE
## operand already stopped it, so a LATER '--' is the command env tries to exec
## ('env: --: No such file'), and the chown never runs. The peeler must NOT treat
## this '--' as an option terminator and flag the chown (that is a false positive).
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/safe-env-dashdash' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env PATH=/usr/bin -- LANG=C chown --recursive root:root "/home/${tu}/nope"
EOF

## SAFE: a '=' that is only EXPANSION SYNTAX ('${v:=default}', '$((a=1))') is not
## an env NAME=VALUE operand -- the word expands to a value with no '=', so env
## execs THAT word and the chown never runs. The peeler must test the LITERAL
## text, not the raw source, or it skips the word and false-flags the chown.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/safe-env-expand' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
env -- "${envx:=true}" chown --recursive root:root "/home/${tu}/nope"
EOF

## SAFE round-2 counterparts that must stay clean: 'command -V' only DESCRIBES,
## dd 'if=' is a READ (only 'of=' writes), 'chmod +w' is umask-filtered, and a
## 'source FILE -- args' sources FILE (safe path), not the '--' argument.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/safe-round2' <<'EOF'
#!/bin/bash
root_check() {
   [ "$(id -u)" = "0" ] || exit 1
}
root_check
tu="$1"
command -V chown
dd if="/home/${tu}/data" of=/var/lib/targetpkg/out
chmod +w /etc/targetpkg.conf
source /usr/lib/targetpkg/safe.sh -- "/home/${tu}/evil"
EOF

## NOT-SHIPPED: a self-gated root helper under ci/ (no FHS install path). Even
## with a real home-write vuln it is NOT a root entry point on a user system, so
## it must NOT enter the root surface (regression: root-guard reachability was
## once tree-wide and flagged CI/test scripts).
write 'packages/kicksecure/targetpkg/ci/vuln-ci.sh' <<'EOF'
#!/bin/bash
root_check() {
   if [ "$(id -u)" != "0" ]; then
      echo "ERROR: must be run as root!"
      exit 1
   fi
}
root_check
target_user="$1"
chown --recursive "${target_user}:${target_user}" "/home/${target_user}"
EOF

## SAFE self-gated helper: validated user (getent), absolute non-home, safe mode.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/safe-guarded#targetpkg-shared' <<'EOF'
#!/bin/bash
require_root() {
   if [ "$(id -u)" != "0" ]; then
      echo "ERROR: must be run as root!"
      exit 1
   fi
}
require_root
user_name="$1"
if ! getent passwd "${user_name}" >/dev/null ; then
   exit 1
fi
install -m 0700 -o root -g root /dev/null /var/lib/targetpkg/state
EOF

## SAFE: a user-only launcher whose OWN root_check REFUSES root (tb-starter
## torbrowser shape). The helper name alone must not make it a root entry point.
write 'packages/kicksecure/targetpkg/usr/bin/safe-refuses-root#targetpkg-shared' <<'EOF'
#!/bin/bash
root_check() {
   if [ "$(id -u)" != "0" ]; then
      true
   else
      printf '%s\n' "Do not run ${0} as root!"
      exit 1
   fi
}
root_check
done_file="${HOME}/.tb/first-boot-home-population.done"
cp --recursive --no-clobber /var/cache/tb-binary/.cache "${HOME}/"
touch "${done_file}"
EOF

## SAFE: an inline refusal whose message embeds the root-require phrase
## 'run this as root' (developer-meta-files dm-upload-canary shape).
write 'packages/kicksecure/targetpkg/usr/bin/safe-text-refusal#targetpkg-shared' <<'EOF'
#!/bin/bash
if [ "$(id -u)" = "0" ]; then
   echo "ERROR: Do not run this as root!"
   exit 1
fi
. "${HOME}/derivative-maker/help-steps/pre"
EOF

## VULN: a real root gate; a refusal phrase OUTSIDE root_check's own body (about
## a different program) must not cancel it.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-refusal-elsewhere#targetpkg-shared' <<'EOF'
#!/bin/bash
root_check() {
   if [ "$(id -u)" != "0" ]; then
      echo "ERROR: must be run as root!"
      exit 1
   fi
}
root_check
echo "Note: do not run the browser as root."
home_folder="/home/$1"
find "${home_folder}" -name '*.tmp' -delete
EOF

## VULN: a real root_check whose OWN body also carries refusal-looking text (a
## 'not_as_root' comment, a 'do not run as root' note). Both directions in one
## body -> still a root gate.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-mixed-body#targetpkg-shared' <<'EOF'
#!/bin/bash
root_check() {
   # not_as_root
   if [ "$(id -u)" != "0" ]; then
      echo "ERROR: must be run as root!"
      exit 1
   fi
   echo "Note: do not run as root without sudo logging."
}
root_check
home_folder="/home/$1"
find "${home_folder}" -name '*.tmp' -delete
EOF

## VULN: TEXT-signal root gate whose message spans 'do not run ... as root'
## across clauses; must not read as a refusal.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-text-cross-clause#targetpkg-shared' <<'EOF'
#!/bin/bash
if [ "$(id -u)" != "0" ]; then
   echo "Do not run as a regular user, this script must be run as root."
   exit 1
fi
echo "Note: do not run the browser as root."
home_folder="/home/$1"
find "${home_folder}" -name '*.tmp' -delete
EOF

## VULN: TEXT-signal root gate beside a separate one-word refusal; the refusal
## must not cancel the remaining 'must be run as root'.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-text-both#targetpkg-shared' <<'EOF'
#!/bin/bash
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: this helper must be run as root."
   exit 1
fi
echo "Tip: do not run it as root from a desktop session."
find "/home/$1" -name '*.tmp' -delete
EOF

## VULN + WAIVER: pins the per-line by-design waiver. Every sink is a real
## candidate; a '## style-ok: lpe-<rule> -- <why>' comment must route ONLY the
## named rule to 'suppressed' (still visible), leaving intact: every OTHER rule
## on the same statement, an identical UN-waived sink, and a reason-less waiver.
## The continuation sink pins the walk-up past a '\' line continuation. A
## waiver wrapped over a contiguous standalone comment block is honored;
## one cut off by a blank or code line is not.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln-waived#targetpkg-shared' <<'EOF'
#!/bin/bash
root_check() {
   if [ "$(id -u)" != "0" ]; then
      echo "ERROR: must be run as root!"
      exit 1
   fi
}
root_check
tu="$1"
home="/home/${tu}"
## style-ok: lpe-symlink-follow -- reviewed by-design, single-line waiver
cp --dereference /etc/skel/.bashrc "${home}/.bashrc"
cp --dereference /etc/skel/.profile "${home}/.profile"
## style-ok: lpe-world-writable-perms
chmod 777 "${home}/pub"
## style-ok: lpe-home-recursive-write -- reviewed, continuation form
chown --recursive "${tu}:${tu}" \
   "${home}/.config"
## style-ok: lpe-symlink-follow -- decoy: must NOT reach the cp below (a separate statement)
echo "harmless" # a comment that ends with a backslash \
cp --dereference /etc/skel/.bash_logout "${home}/.bash_logout"
echo "reminder: #style-ok: lpe-symlink-follow -- smuggled via a quoted string" # a real but unrelated trailing comment
cp --dereference /etc/skel/.bash_history "${home}/.bash_history"
home_var=1 ## style-ok: lpe-symlink-follow -- TRAILING waiver for home_var only, must NOT reach the cp below
cp --dereference /etc/skel/.inputrc "${home}/.inputrc"
echo continued-echo \
## style-ok: lpe-symlink-follow -- comment is a CONTINUATION of the echo above (a '\' line), NOT a standalone waiver
cp --dereference /etc/skel/.dircolors "${home}/.dircolors"
## style-ok: lpe-symlink-follow -- wrapped reason, first line
## of a two-line waiver block.
cp --dereference /etc/skel/.wrap2 "${home}/.wrap2"
## style-ok: lpe-symlink-follow -- wrapped reason, first line
## of a three-line waiver block,
## third line.
cp --dereference /etc/skel/.wrap3 "${home}/.wrap3"
## Unrelated prose opening the block.
## style-ok: lpe-symlink-follow -- waiver on the middle line,
## reason wrapped below it.
cp --dereference /etc/skel/.wrapmid "${home}/.wrapmid"
## style-ok: lpe-symlink-follow -- separated by a BLANK line, must NOT reach the cp below

cp --dereference /etc/skel/.blanksep "${home}/.blanksep"
## style-ok: lpe-symlink-follow -- separated by a CODE line, must NOT reach the cp below
true
## Comment block of the cp below, with no waiver of its own.
cp --dereference /etc/skel/.codesep "${home}/.codesep"
## Prose quoting the form: ## style-ok: lpe-symlink-follow -- example only, not a waiver
cp --dereference /etc/skel/.quoted "${home}/.quoted"
## style-ok: lpe-symlink-follow -- waiver line ending in a comment backslash \
## that does not continue anything.
cp --dereference /etc/skel/.cbs "${home}/.cbs"
## style-ok: lpe-symlink-follow -- far block reason
cp --dereference /etc/skel/.near "${home}/.near" ## style-ok: lpe-symlink-follow -- near trailing reason
EOF

## VULN + WAIVER (python path): the python-advisory scanner must ALSO reject a
## 'style-ok' smuggled inside a multi-line string. The subprocess+escalator line
## makes the enum flag the file root-reachable; the os.chown on a /home path is
## the advisory finding that MUST stay flagged despite the string-embedded text.
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln_py_waived.py' <<'EOF'
#!/usr/bin/python3
import os
import subprocess
subprocess.run(["sudo", "systemctl", "restart", "unit"])
_DOC = """documentation line
# style-ok: lpe-python-advisory -- smuggled inside a multi-line string, not a waiver"""
os.chown("/home/user/.config", 0, 0)
marker_py = 1  # style-ok: lpe-python-advisory -- TRAILING waiver for marker_py only, must NOT reach the os.chown below
os.chown("/home/user/.ssh", 0, 0)
if marker_py:
    pass
    # style-ok: lpe-python-advisory -- closes the if suite, must NOT reach the os.chown below
os.chown("/home/user/.cache", 0, 0)
# style-ok: lpe-python-advisory -- wrapped python waiver,
# second line.
os.chown("/home/user/.local", 0, 0)
# style-ok: lpe-python-advisory -- waiver above a multi-line statement
chowned = [
    os.chown("/home/user/.multiline", 0, 0),
]
# style-ok: lpe-python-advisory -- waives the if header only, must NOT reach the body
if chowned:
    os.chown("/home/user/.ifbody", 0, 0)
# style-ok: lpe-python-advisory -- waives the if header, must NOT reach the one-liner body
if chowned: os.chown("/home/user/.if1liner", 0, 0)
# style-ok: lpe-python-advisory -- waives the for header, must NOT reach the one-liner body
for _ in chowned: os.chown("/home/user/.for1liner", 0, 0)
# style-ok: lpe-python-advisory -- waives the with header, must NOT reach the one-liner body
with open("/dev/null") as _h: os.chown("/home/user/.with1liner", 0, 0)
# style-ok: lpe-python-advisory -- waives the def header, must NOT reach the one-liner body
def _oneliner(): os.chown("/home/user/.def1liner", 0, 0)
# style-ok: lpe-python-advisory -- documents the assignment, must NOT reach the post-';' op
marker_semi = 1; os.chown("/home/user/.semicolon", 0, 0)
# style-ok: lpe-python-advisory -- if header, WRAPPED one-liner body must NOT be reached
if chowned: (
    os.chown("/home/user/.ifwrap1liner", 0, 0))
if not chowned:
    pass
# style-ok: lpe-python-advisory -- else header ('else' is no ast node), one-liner body must NOT be reached
else: os.chown("/home/user/.else1liner", 0, 0)
try:
    pass
# style-ok: lpe-python-advisory -- finally header ('finally' is no ast node), one-liner body must NOT be reached
finally: os.chown("/home/user/.finally1liner", 0, 0)
# style-ok: lpe-python-advisory -- the sink IS in the header; precision canary, MUST suppress
if os.chown("/home/user/.ifheader", 0, 0): pass
def _mark(_f):
    return _f
# style-ok: lpe-python-advisory -- a DECORATED def leads its line at '@'; waiver MUST reach the header sink
@_mark
def _deco_hdr(_p=os.chown("/home/user/.decohdr", 0, 0)):
    pass
try:
    pass
# style-ok: lpe-python-advisory -- waiver above a wrapped except header
except (
    os.chown("/home/user/.excepthdr", 0, 0)
):
    pass
match chowned:
    # style-ok: lpe-python-advisory -- waiver above a wrapped case guard
    case [_] if (
        os.chown("/home/user/.caseguard", 0, 0)
    ):
        pass
    # style-ok: lpe-python-advisory -- waiver above a case whose pattern wraps
    case (
        [_, _]
    ) if (
        os.chown("/home/user/.caseparen", 0, 0)
    ):
        pass
    case (
        [_, _, _]  # style-ok: lpe-python-advisory -- TRAILING on the pattern line, must NOT reach the guard
    ) if (
        os.chown("/home/user/.casetrail", 0, 0)
    ):
        pass
EOF

## VULN + WAIVER (python form feed): a form feed is NOT a line break to Python,
## so the advisory's line numbers must not count it as one -- else the op below
## is reported one line low, ON the waiver comment, and wrongly suppressed.
form_feed=$'\f'
printf '%s\n' \
   '#!/usr/bin/python3' \
   'import os' \
   'import subprocess' \
   'subprocess.run(["sudo", "systemctl", "restart", "unit"])' \
   "# page break${form_feed} inside a comment" \
   'os.chown("/home/user/.formfeed", 0, 0)' \
   '# style-ok: lpe-python-advisory -- waives the list below only' \
   'waived = [' \
   '    0,' \
   ']' \
   | write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln_py_formfeed.py'

## VULN + WAIVER (python parse error): the file tokenizes but does not parse, so
## it has no trustworthy statement boundaries -- even a waiver directly above
## the advisory must NOT be honored (fail safe: the finding stays).
write 'packages/kicksecure/targetpkg/usr/libexec/targetpkg/vuln_py_unparsed.py' <<'EOF'
#!/usr/bin/python3
import os
import subprocess
subprocess.run(["sudo", "systemctl", "restart", "unit"])
# style-ok: lpe-python-advisory -- must NOT be honored in an unparseable file
os.chown("/home/user/.unparsed", 0, 0)
broken = = 1
EOF

## --- run the real tool + delegate assertions --------------------------------

json="${work_dir}/out.json"
populated_rc=0
"${subject}" "${work_dir}" > "${json}" 2>"${work_dir}/err" || populated_rc=$?

if [ "${populated_rc}" -ne 0 ]; then
   printf '%s\n' "FATAL: dm-root-lpe-audit exited ${populated_rc}" >&2
   cat -- "${work_dir}/err" >&2
   exit 1
fi

"${checker}" "${json}"
