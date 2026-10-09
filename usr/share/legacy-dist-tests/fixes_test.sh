#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The inline 'bash -c' programs run in a deliberately separate child shell.
## style-ok: allow-embedded-script

## legacy-dist 'fixes': source-ability + every fix function.
##
## Drives the REAL script. It is source-able (was_executed guard, strict-mode
## confined to main()), so this test sources it and calls each pure function
## with the two testability seams pointed at a tmpdir:
##   - LEGACY_DIST_TEST_ROOT prefixes the host state paths (/var, /etc, /home, ...).
##   - HELPER_SCRIPTS_PATH prefixes the sourced libs AND the executed helper-scripts,
##     so a composite tree supplies the real libs plus mock get-user-list /
##     check-image-builtin-mok / shim-signed-mok-setup.
## PATH-shadow mocks cover the root/non-deterministic commands (sudo, locale-gen,
## qubesdb-read); real deterministic tools (sed, grep, cat, str_replace, sponge,
## safe-rm) run for real. All home-folder ops go through 'sudo -u user', so the
## mock sudo runs them as the current (test) user against the tmpdir.
##
## A missing subject or helper-scripts lib is a HARD FAIL (exit 1), never a skip.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LEGACY_DIST_REPO ] || LEGACY_DIST_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${LEGACY_DIST_REPO}" ]; then
   subject="${LEGACY_DIST_REPO}/usr/libexec/legacy-dist/fixes"
else
   subject='/usr/libexec/legacy-dist/fixes'
fi
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   real_hs_libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
   real_hs_bindir="${HELPER_SCRIPTS_REPO}/usr/bin"
else
   real_hs_libdir='/usr/libexec/helper-scripts'
   real_hs_bindir='/usr/bin'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set LEGACY_DIST_REPO to a legacy-dist checkout, or install legacy-dist" >&2
   exit 1
fi
if [ ! -r "${real_hs_libdir}/check_runtime.bsh" ] || [ ! -r "${real_hs_libdir}/has.bsh" ]; then
   printf '%s\n' "FATAL: helper-scripts libs not readable under '${real_hs_libdir}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

## --- composite HELPER_SCRIPTS_PATH tree: real libs + mock helper-scripts ---
hs_tree="${test_dir}/hs"
mkdir --parents -- "${hs_tree}/usr/libexec/helper-scripts" "${hs_tree}/usr/sbin"
for real_file in "${real_hs_libdir}"/* ; do
   ln -s -- "${real_file}" "${hs_tree}/usr/libexec/helper-scripts/$(basename -- "${real_file}")"
done
## The executed helper-scripts are mocked (real ones probe the live system).
safe-rm -f -- \
   "${hs_tree}/usr/libexec/helper-scripts/get-user-list" \
   "${hs_tree}/usr/libexec/helper-scripts/check-image-builtin-mok"

cat > "${hs_tree}/usr/libexec/helper-scripts/get-user-list" <<'EOF'
#!/bin/bash
## mock get-user-list: emit $GUL_USERS (newline-separated), exit $GUL_RC.
rc="${GUL_RC:-0}"
[ "${rc}" = 0 ] || exit "${rc}"
printf '%s\n' "${GUL_USERS:-user}"
EOF

cat > "${hs_tree}/usr/libexec/helper-scripts/check-image-builtin-mok" <<'EOF'
#!/bin/bash
## mock check-image-builtin-mok: 0 safe, 1 vulnerable-but-wipeable, other = leave alone.
exit "${CIBM_RC:-0}"
EOF

cat > "${hs_tree}/usr/sbin/shim-signed-mok-setup" <<'EOF'
#!/bin/bash
## mock shim-signed-mok-setup: only dkms_mok_variables_set is used, pointed at
## the test's MOK files. Sourcing must have no side effects.
dkms_mok_variables_set() {
   dkms_mok_public_file="${MOK_PUB:-}"
   dkms_mok_private_file="${MOK_KEY:-}"
}
EOF

chmod +x -- \
   "${hs_tree}/usr/libexec/helper-scripts/get-user-list" \
   "${hs_tree}/usr/libexec/helper-scripts/check-image-builtin-mok"

## --- PATH-shadow mocks for root / non-deterministic commands ---
mockbin="${test_dir}/bin"
mkdir --parents -- "${mockbin}"

cat > "${mockbin}/sudo" <<'EOF'
#!/bin/bash
## mock sudo: strip sudo options (--non-interactive -u USER --) and run the
## command as the current (test) user. All home-folder ops flow through here.
while [ "$#" -gt 0 ]; do
   case "$1" in
      --non-interactive) shift ;;
      -u) shift 2 ;;
      --) shift; break ;;
      *) break ;;
   esac
done
exec "$@"
EOF

cat > "${mockbin}/locale-gen" <<'EOF'
#!/bin/bash
## mock locale-gen: record the invocation (real one needs root and rewrites the host).
[ -z "${LOCALEGEN_MARKER:-}" ] || touch -- "${LOCALEGEN_MARKER}"
exit 0
EOF

cat > "${mockbin}/qubesdb-read" <<'EOF'
#!/bin/bash
## mock qubesdb-read: emit $QUBESDB_NAME, exit $QUBESDB_RC.
rc="${QUBESDB_RC:-0}"
[ "${rc}" = 0 ] || exit "${rc}"
printf '%s\n' "${QUBESDB_NAME:-host}"
EOF

cat > "${mockbin}/id" <<'EOF'
#!/bin/bash
## mock id: the expected account always "exists". Decouples the success cases
## from host accounts (CI may run with no 'user' account); the failbin variant
## (exit 1) drives the "missing user" cases.
exit 0
EOF

chmod +x -- "${mockbin}/sudo" "${mockbin}/locale-gen" "${mockbin}/qubesdb-read" "${mockbin}/id"
## mockbin shadows the root/non-deterministic commands; real_hs_bindir supplies
## str_replace from the helper-scripts checkout.
export PATH="${mockbin}:${real_hs_bindir}:${PATH}"

## A PATH whose 'id' always fails, for the "user does not exist" branch.
failbin="${test_dir}/failbin"
mkdir --parents -- "${failbin}"
cat > "${failbin}/id" <<'EOF'
#!/bin/bash
exit 1
EOF
chmod +x -- "${failbin}/id"

## The subject resolves its libs + executed helper-scripts via this tree.
export HELPER_SCRIPTS_PATH="${hs_tree}"

## Mock behaviour defaults (each case overrides what it needs).
export GUL_USERS='user'
export GUL_RC=0
export CIBM_RC=0
export QUBESDB_NAME='host'
export QUBESDB_RC=0
unset MOK_PUB MOK_KEY LOCALEGEN_MARKER 2>/dev/null || true

## --------------------------------------------------------------------------
pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## true if the path exists (file, dir or symlink), else false -- as a word.
exists() {
   if [ -e "$1" ]; then printf '%s' "yes"; else printf '%s' "no"; fi
}

## Run a fix function with errexit disabled inside it (as main() does via '|| true'),
## capturing its return code.
call_fn() {
   local rc=0
   "$@" || rc=$?
   printf '%s' "${rc}"
}

reset_user_list() {
   user_list=()
   user_list_already_loaded='false'
}

## Start a fresh, empty per-case root and point the subject's seam at it. Sets
## the global 'r' and exports LEGACY_DIST_TEST_ROOT. Must run in THIS shell (not
## a command-substitution subshell) so the export survives into later calls.
new_root() {
   r="$(mktemp --directory --tmpdir="${test_dir}" root.XXXXXX)"
   export LEGACY_DIST_TEST_ROOT="${r}"
}

do_once() {
   ## path of a whonix do_once marker under a root
   printf '%s' "${1}/var/lib/whonix/do_once/${2}"
}

## ================= source-ability (BEFORE the in-process source) =================
## These run in an ISOLATED subprocess and MUST precede the in-process source
## below. They verify the subject is inert when sourced (no strict-mode leak, no
## auto-run). If the subject regressed to run at file scope, sourcing it into THIS
## shell would exit or side-effect before any check -- and, run as root, bypass the
## seams onto the host -- so the in-process source is GATED on these passing.
## $0 is a placeholder, NOT the subject: was_executed compares BASH_SOURCE[0] to $0.
leak_rc=0
HELPER_SCRIPTS_PATH="${hs_tree}" bash -c 'source "$1"; false; true' placeholder "${subject}" >/dev/null 2>&1 \
   || leak_rc=$?
check "sourcing does not leak strict-mode" "${leak_rc}" "0"

src_out="$(HELPER_SCRIPTS_PATH="${hs_tree}" bash -c 'source "$1"' placeholder "${subject}" 2>&1)" || true
check "sourcing does not auto-run" "${src_out}" ""

if [ "${leak_rc}" -ne 0 ] || [ -n "${src_out}" ]; then
   printf '%s\n' "FATAL: subject is not safe to source in-process (see checks above)" >&2
   exit 1
fi

# shellcheck disable=SC1090
source "${subject}"

## Required REAL tools (the mocked sudo/locale-gen/qubesdb-read/id are provided by
## mockbin). Absent means a broken test environment -> FATAL, never a skip.
## 'has' comes from the just-sourced has.bsh.
for tool in sed grep cat stat str_replace sponge safe-rm ; do
   if ! has "${tool}" ; then
      printf '%s\n' "FATAL: required tool '${tool}' not on PATH" >&2
      exit 1
   fi
done

check "run_as_user is defined"     "$(type -t run_as_user)"     "function"
check "load_user_list is defined"  "$(type -t load_user_list)"  "function"
check "main is defined"            "$(type -t main)"            "function"

## Called in THIS shell (not call_fn's subshell) so the global user_list mutation
## is observable. '|| rc=$?' keeps errexit off inside, as main()'s '|| true' does.
reset_user_list
GUL_USERS='user'; GUL_RC=0
rc=0; load_user_list || rc=$?
check "load_user_list: rc 0 on success" "${rc}" "0"
check "load_user_list: parses one user" "${user_list[*]}" "user"
check "load_user_list: marks loaded"     "${user_list_already_loaded}" "true"

## Idempotent: a second call does NOT re-run get-user-list (cached list wins).
GUL_USERS='someone-else'
rc=0; load_user_list || rc=$?
check "load_user_list: cached, no re-fetch" "${user_list[*]}" "user"

reset_user_list
GUL_RC=1
rc=0; load_user_list || rc=$?
check "load_user_list: rc 1 when get-user-list fails" "${rc}" "1"
GUL_RC=0; GUL_USERS='user'

## ===================== command_not_found_sources_list_fix =====================
new_root; mkdir --parents -- "${r}/etc/apt"
rc="$(call_fn command_not_found_sources_list_fix)"
check "cnf_sources_list: creates missing sources.list" "$(exists "${r}/etc/apt/sources.list")" "yes"
check "cnf_sources_list: writes do_once marker" \
   "$(exists "$(do_once "${r}" command_not_found_sources_list_fix_version_1)")" "yes"

## Existing sources.list is left untouched (not truncated).
new_root; mkdir --parents -- "${r}/etc/apt"; printf '%s\n' "deb example" > "${r}/etc/apt/sources.list"
rc="$(call_fn command_not_found_sources_list_fix)"
check "cnf_sources_list: existing file preserved" "$(cat -- "${r}/etc/apt/sources.list")" "deb example"

## Idempotent: marker present -> no work (sources.list not created).
new_root; mkdir --parents -- "$(dirname -- "$(do_once "${r}" x)")"
touch -- "$(do_once "${r}" command_not_found_sources_list_fix_version_1)"
rc="$(call_fn command_not_found_sources_list_fix)"
check "cnf_sources_list: idempotent (no sources.list)" "$(exists "${r}/etc/apt/sources.list")" "no"

## ===================== command_not_found_permission_fix =====================
new_root; mkdir --parents -- "${r}/var/lib/command-not-found"
touch -- "${r}/var/lib/command-not-found/commands.db"; chmod 600 -- "${r}/var/lib/command-not-found/commands.db"
rc="$(call_fn command_not_found_permission_fix)"
check "cnf_perm: adds other-read to commands.db" \
   "$(stat -c '%a' -- "${r}/var/lib/command-not-found/commands.db")" "604"
check "cnf_perm: writes do_once marker" \
   "$(exists "$(do_once "${r}" command_not_found_permission_fix_version_1)")" "yes"

## No db present: still writes the marker, no error.
new_root
rc="$(call_fn command_not_found_permission_fix)"
check "cnf_perm: marker written even with no db" \
   "$(exists "$(do_once "${r}" command_not_found_permission_fix_version_1)")" "yes"

## Idempotent: marker present -> chmod not applied.
new_root; mkdir --parents -- "${r}/var/lib/command-not-found" "$(dirname -- "$(do_once "${r}" x)")"
touch -- "${r}/var/lib/command-not-found/commands.db"; chmod 600 -- "${r}/var/lib/command-not-found/commands.db"
touch -- "$(do_once "${r}" command_not_found_permission_fix_version_1)"
rc="$(call_fn command_not_found_permission_fix)"
check "cnf_perm: idempotent (mode unchanged)" \
   "$(stat -c '%a' -- "${r}/var/lib/command-not-found/commands.db")" "600"

## ===================== bisq_desktop_directories_workaround =====================
bisq_tor() { printf '%s' "${1}/home/user/.local/share/Bisq/btc_mainnet/tor/tor"; }

## No whonix marker -> early return, nothing written.
new_root; mkdir --parents -- "${r}/home/user"
rc="$(call_fn bisq_desktop_directories_workaround)"
check "bisq: no whonix marker -> skip" \
   "$(exists "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)")" "no"

## Marker + user + home, non-templatevm, non-dvm name -> creates bisq dir + marker.
new_root; mkdir --parents -- "${r}/usr/share/whonix" "${r}/home/user"
touch -- "${r}/usr/share/whonix/marker"; QUBESDB_NAME='host'
rc="$(call_fn bisq_desktop_directories_workaround)"
check "bisq: creates bisq tor file" "$(exists "$(bisq_tor "${r}")")" "yes"
check "bisq: writes do_once marker" \
   "$(exists "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)")" "yes"

## Qubes DVM Template name -> skip.
new_root; mkdir --parents -- "${r}/usr/share/whonix" "${r}/home/user"
touch -- "${r}/usr/share/whonix/marker"; QUBESDB_NAME='anon-whonix-dvm'
rc="$(call_fn bisq_desktop_directories_workaround)"
check "bisq: -dvm name -> skip" \
   "$(exists "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)")" "no"
QUBESDB_NAME='host'

## this-is-templatevm present -> skip.
new_root; mkdir --parents -- "${r}/usr/share/whonix" "${r}/home/user" "${r}/run/qubes"
touch -- "${r}/usr/share/whonix/marker"; touch -- "${r}/run/qubes/this-is-templatevm"
rc="$(call_fn bisq_desktop_directories_workaround)"
check "bisq: templatevm -> skip" \
   "$(exists "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)")" "no"

## Bisq tor file already present -> skip (no marker written).
new_root; mkdir --parents -- "${r}/usr/share/whonix" "$(dirname -- "$(bisq_tor "${r}")")"
touch -- "${r}/usr/share/whonix/marker"; touch -- "$(bisq_tor "${r}")"
rc="$(call_fn bisq_desktop_directories_workaround)"
check "bisq: existing bisq file -> skip marker" \
   "$(exists "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)")" "no"

## User does not exist -> skip (id fails).
new_root; mkdir --parents -- "${r}/usr/share/whonix" "${r}/home/user"
touch -- "${r}/usr/share/whonix/marker"
rc="$(PATH="${failbin}:${PATH}" call_fn bisq_desktop_directories_workaround)"
check "bisq: missing user -> skip" \
   "$(exists "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)")" "no"

## Idempotent: marker present -> no bisq file created.
new_root; mkdir --parents -- "${r}/usr/share/whonix" "${r}/home/user" "$(dirname -- "$(do_once "${r}" x)")"
touch -- "${r}/usr/share/whonix/marker"; touch -- "$(do_once "${r}" bisq_desktop_directories_workaround_version_1)"
rc="$(call_fn bisq_desktop_directories_workaround)"
check "bisq: idempotent (no bisq file)" "$(exists "$(bisq_tor "${r}")")" "no"

## ============================== locales_fix ==============================
## Empty (comments/blank only) locale.gen -> uncomment + locale-gen + marker.
new_root; mkdir --parents -- "${r}/etc"
printf '%s\n' '# en_US.UTF-8 UTF-8' '# other comment' '' > "${r}/etc/locale.gen"
export LOCALEGEN_MARKER="${r}/locale-gen.ran"
rc="$(call_fn locales_fix)"
check "locales_fix: uncomments en_US line" \
   "$(grep -c -- '^en_US.UTF-8 UTF-8$' "${r}/etc/locale.gen")" "1"
check "locales_fix: runs locale-gen" "$(exists "${LOCALEGEN_MARKER}")" "yes"
check "locales_fix: writes do_once marker" \
   "$(exists "$(do_once "${r}" locales_fix_version_1)")" "yes"
unset LOCALEGEN_MARKER

## Already-populated locale.gen -> skip (no marker).
new_root; mkdir --parents -- "${r}/etc"
printf '%s\n' 'en_GB.UTF-8 UTF-8' > "${r}/etc/locale.gen"
export LOCALEGEN_MARKER="${r}/locale-gen.ran"
rc="$(call_fn locales_fix)"
check "locales_fix: populated file -> skip locale-gen" "$(exists "${LOCALEGEN_MARKER}")" "no"
check "locales_fix: populated file -> no marker" \
   "$(exists "$(do_once "${r}" locales_fix_version_1)")" "no"
unset LOCALEGEN_MARKER

## Missing locale.gen -> skip.
new_root
rc="$(call_fn locales_fix)"
check "locales_fix: missing file -> skip" \
   "$(exists "$(do_once "${r}" locales_fix_version_1)")" "no"

## ============================= zsh_migration =============================
## AppVM -> do_once folder under /usr/local; creates .zshrc.
new_root; mkdir --parents -- "${r}/home/user" "${r}/run/qubes"; touch -- "${r}/run/qubes/this-is-appvm"
rc="$(call_fn zsh_migration)"
check "zsh: appvm creates .zshrc" "$(exists "${r}/home/user/.zshrc")" "yes"
check "zsh: appvm do_once under /usr/local" \
   "$(exists "${r}/usr/local/var/lib/kicksecure/do_once/zsh_migration_version_1")" "yes"

## Non-AppVM -> do_once folder under /var/lib.
new_root; mkdir --parents -- "${r}/home/user"
rc="$(call_fn zsh_migration)"
check "zsh: non-appvm creates .zshrc" "$(exists "${r}/home/user/.zshrc")" "yes"
check "zsh: non-appvm do_once under /var/lib" \
   "$(exists "${r}/var/lib/kicksecure/do_once/zsh_migration_version_1")" "yes"

## Existing .zshrc -> skip.
new_root; mkdir --parents -- "${r}/home/user"; touch -- "${r}/home/user/.zshrc"
rc="$(call_fn zsh_migration)"
check "zsh: existing .zshrc -> no do_once" \
   "$(exists "${r}/var/lib/kicksecure/do_once/zsh_migration_version_1")" "no"

## Missing user -> skip.
new_root; mkdir --parents -- "${r}/home/user"
rc="$(PATH="${failbin}:${PATH}" call_fn zsh_migration)"
check "zsh: missing user -> skip" \
   "$(exists "${r}/var/lib/kicksecure/do_once/zsh_migration_version_1")" "no"

## ===================== qterminal_confirm_multiline_paste =====================
qt_ini() { printf '%s' "${1}/home/${2}/.config/qterminal.org/qterminal.ini"; }

new_root; reset_user_list; GUL_USERS='user'
mkdir --parents -- "$(dirname -- "$(qt_ini "${r}" user)")"
printf '%s\n' '[General]' 'ConfirmMultilinePaste=false' > "$(qt_ini "${r}" user)"
rc="$(call_fn qterminal_confirm_multiline_paste)"
check "qterminal_multiline: false -> true" \
   "$(grep -c -- '^ConfirmMultilinePaste=true$' "$(qt_ini "${r}" user)")" "1"
check "qterminal_multiline: writes do_once" \
   "$(exists "$(do_once "${r}" qterminal_confirm_multiline_paste_version_2)")" "yes"

## Already true -> left as-is.
new_root; reset_user_list; GUL_USERS='user'
mkdir --parents -- "$(dirname -- "$(qt_ini "${r}" user)")"
printf '%s\n' 'ConfirmMultilinePaste=true' > "$(qt_ini "${r}" user)"
rc="$(call_fn qterminal_confirm_multiline_paste)"
check "qterminal_multiline: already true unchanged" \
   "$(cat -- "$(qt_ini "${r}" user)")" "ConfirmMultilinePaste=true"

## Two users -> both rewritten.
new_root; reset_user_list; GUL_USERS=$'user\nuser2'
for u in user user2 ; do
   mkdir --parents -- "$(dirname -- "$(qt_ini "${r}" "${u}")")"
   printf '%s\n' 'ConfirmMultilinePaste=false' > "$(qt_ini "${r}" "${u}")"
done
rc="$(call_fn qterminal_confirm_multiline_paste)"
check "qterminal_multiline: user rewritten"  "$(grep -c -- '^ConfirmMultilinePaste=true$' "$(qt_ini "${r}" user)")" "1"
check "qterminal_multiline: user2 rewritten" "$(grep -c -- '^ConfirmMultilinePaste=true$' "$(qt_ini "${r}" user2)")" "1"
GUL_USERS='user'

## No ini -> marker still written.
new_root; reset_user_list; GUL_USERS='user'
rc="$(call_fn qterminal_confirm_multiline_paste)"
check "qterminal_multiline: no ini -> marker written" \
   "$(exists "$(do_once "${r}" qterminal_confirm_multiline_paste_version_2)")" "yes"

## ========================= qterminal_bookmarks_file =========================
new_root; reset_user_list; GUL_USERS='user'
mkdir --parents -- "$(dirname -- "$(qt_ini "${r}" user)")"
printf '%s\n' '[General]' \
   'BookmarksFile=/home/user/.config/qterminal.org/qterminal_bookmarks.xml' \
   'Keep=me' > "$(qt_ini "${r}" user)"
rc="$(call_fn qterminal_bookmarks_file)"
check "qterminal_bookmarks: BookmarksFile line removed" \
   "$(grep -c -- '^BookmarksFile=' "$(qt_ini "${r}" user)")" "0"
check "qterminal_bookmarks: other lines kept" \
   "$(grep -c -- '^Keep=me$' "$(qt_ini "${r}" user)")" "1"
check "qterminal_bookmarks: writes do_once" \
   "$(exists "$(do_once "${r}" qterminal_bookmarks_file_version_2)")" "yes"

## ===================== pcmanfm_qt_removable_media_automount =====================
pcm_conf() { printf '%s' "${1}/home/user/.config/pcmanfm-qt/${2}/settings.conf"; }

new_root; reset_user_list; GUL_USERS='user'
for v in lxqt default ; do
   mkdir --parents -- "$(dirname -- "$(pcm_conf "${r}" "${v}")")"
   printf '%s\n' 'MountOnStartup=true' 'MountRemovable=true' > "$(pcm_conf "${r}" "${v}")"
done
rc="$(call_fn pcmanfm_qt_removable_media_automount)"
check "pcmanfm_automount: lxqt MountOnStartup off"  "$(grep -c -- '^MountOnStartup=false$' "$(pcm_conf "${r}" lxqt)")" "1"
check "pcmanfm_automount: lxqt MountRemovable off"  "$(grep -c -- '^MountRemovable=false$' "$(pcm_conf "${r}" lxqt)")" "1"
check "pcmanfm_automount: default variant off"      "$(grep -c -- '^MountRemovable=false$' "$(pcm_conf "${r}" default)")" "1"
check "pcmanfm_automount: writes do_once" \
   "$(exists "$(do_once "${r}" pcmanfm_qt_removable_media_automount_version_2)")" "yes"

## ============================= pcmanfm_qt_archiver =============================
new_root; reset_user_list; GUL_USERS='user'
for v in lxqt default ; do
   mkdir --parents -- "$(dirname -- "$(pcm_conf "${r}" "${v}")")"
   printf '%s\n' 'Archiver=xarchiver' > "$(pcm_conf "${r}" "${v}")"
done
rc="$(call_fn pcmanfm_qt_archiver)"
check "pcmanfm_archiver: lxqt archiver fixed"    "$(grep -c -- '^Archiver=lxqt-archiver$' "$(pcm_conf "${r}" lxqt)")" "1"
check "pcmanfm_archiver: default archiver fixed" "$(grep -c -- '^Archiver=lxqt-archiver$' "$(pcm_conf "${r}" default)")" "1"
check "pcmanfm_archiver: writes do_once" \
   "$(exists "$(do_once "${r}" pcmanfm_qt_archiver_version_2)")" "yes"

## ========================= secure_boot_mok_cleanup =========================
mok_setup() {
   local base="$1"
   mkdir --parents -- "${base}"
   MOK_PUB="${base}/mok.pub"; MOK_KEY="${base}/mok.key"
   export MOK_PUB MOK_KEY
   touch -- "${MOK_PUB}"; touch -- "${MOK_KEY}"
}

## Safe (rc 0) -> keys left in place.
mok_setup "${test_dir}/mok-safe"; CIBM_RC=0
rc="$(call_fn secure_boot_mok_cleanup)"
check "mok_cleanup: safe -> pub kept" "$(exists "${MOK_PUB}")" "yes"
check "mok_cleanup: safe -> key kept" "$(exists "${MOK_KEY}")" "yes"

## Vulnerable-but-wipeable (rc 1) -> keys deleted.
mok_setup "${test_dir}/mok-vuln"; CIBM_RC=1
rc="$(call_fn secure_boot_mok_cleanup)"
check "mok_cleanup: vuln -> pub deleted" "$(exists "${MOK_PUB}")" "no"
check "mok_cleanup: vuln -> key deleted" "$(exists "${MOK_KEY}")" "no"

## Other rc (2) -> keys left in place.
mok_setup "${test_dir}/mok-other"; CIBM_RC=2
rc="$(call_fn secure_boot_mok_cleanup)"
check "mok_cleanup: rc 2 -> pub kept" "$(exists "${MOK_PUB}")" "yes"
check "mok_cleanup: rc 2 -> key kept" "$(exists "${MOK_KEY}")" "yes"
CIBM_RC=0; unset MOK_PUB MOK_KEY

## ================================ summary ================================
printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
