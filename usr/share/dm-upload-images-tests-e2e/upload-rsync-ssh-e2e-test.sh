#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- self-contained e2e; dep presence is checked with command -v (helper-scripts
## has.bsh is not sourced here, to keep the throwaway-sshd harness standalone).

## e2e for the derivative-maker REAL image-upload path: drives the ACTUAL dm-upload-images
## show_files + upload_files (sourced from the dm tree -- it is source-able, so main()'s
## build-variable bootstrap is skipped) against a THROWAWAY localhost sshd, authenticated with a
## freshly auto-generated ed25519 key, via real `rsync` over ssh in --dry-run (rsync's own -n, so
## nothing is written). This exercises the real file-list build + the real rsync-over-ssh loop +
## ssh key auth end to end, which the simulate-by-default build mocks. No root, no network beyond
## localhost; teardown kills the sshd and removes the scratch tree.
##
## CANARY: on a dm-upload-images that is NOT source-able (main auto-runs on source), sourcing it
## would run parse-cmd ("No option chosen") and abort here -- so this test also guards the
## source-able refactor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

case_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"

fail() { printf '%s\n' "FAIL: $1" >&2; exit 1; }

## --- subject: the dm tree's REAL dm-upload-images (wired via DERIVATIVE_MAKER_DIR) ---
dm_dir="${DERIVATIVE_MAKER_DIR:-}"
[ -n "${dm_dir}" ] || fail "DERIVATIVE_MAKER_DIR is unset (dist-ai-tests-all wire)"
subject="${dm_dir}/packages/kicksecure/developer-meta-files/usr/bin/dm-upload-images"
[ -f "${subject}" ] || fail "no dm-upload-images at ${subject}"

## Hard dependencies (an absent one is an ENVIRONMENT bug -> FATAL, never a skip).
sshd_bin=""
for cand in /usr/sbin/sshd /usr/bin/sshd; do
   if [ -x "${cand}" ]; then
      sshd_bin="${cand}"
      break
   fi
done
[ -n "${sshd_bin}" ] || fail "sshd not found (openssh-server)"
command -v rsync >/dev/null || fail "rsync not found"
command -v ssh-keygen >/dev/null || fail "ssh-keygen not found (openssh-client)"
command -v ssh >/dev/null || fail "ssh not found (openssh-client)"
command -v python3 >/dev/null || fail "python3 not found (free-port picker)"

work="$(mktemp --directory)"
sshd_pid=""
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   trap "" EXIT
   [ -z "${sshd_pid}" ] || kill "${sshd_pid}" 2>/dev/null || true
   ## Best-effort: a cleanup failure must not become the script's exit status (errexit +
   ## inherit_errexit are on) and so flip a PASS to a failure. Not a safe-rm||rm fallback.
   safe-rm --recursive --force -- "${work}" || true
   return 0
}
trap cleanup EXIT

## --- throwaway sshd on a free port, authorized with a freshly auto-gen ed25519 key ------------
## The build key idiom (ssh_key_create): `ssh-keygen -o -a 100 -t ed25519 -N ''`.
ssh-keygen -q -o -a 100 -t ed25519 -N '' -C "dm-upload-images-e2e" -f "${work}/id"
ssh-keygen -q -t ed25519 -N '' -f "${work}/hostkey"
cp -- "${work}/id.pub" "${work}/authorized_keys"
chmod 600 "${work}/authorized_keys"

## Kernel-picked free port (standalone helper run via its own shebang, not an inline python -c).
port="$("${case_dir}/pick-free-port.py")"

## PermitRootLogin prohibit-password, NOT 'no': in CI the suite runs AS ROOT, so the pre-flight +
## upload loop below authenticate to THIS sshd as root with the auto-gen key. 'no' refuses every
## root login (sshd logs "ROOT LOGIN REFUSED"), failing the test for an environment reason only.
## 'prohibit-password' allows the key-based root login while PasswordAuthentication/KbdInteractive
## no keep every password path closed -- the key is the sole credential, root or not.
cat > "${work}/sshd_config" <<EOF
Port ${port}
ListenAddress 127.0.0.1
HostKey ${work}/hostkey
AuthorizedKeysFile ${work}/authorized_keys
PidFile ${work}/sshd.pid
UsePAM no
StrictModes no
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers $(id -un)
EOF

"${sshd_bin}" -f "${work}/sshd_config" -D &
sshd_pid=$!

## Readiness-wait on the port via bash /dev/tcp (no inline python), until-loop not a fixed sleep.
## Check sshd is still ALIVE each cycle: if it exited (e.g. its port was already taken -> bind
## failed), fail FAST instead of eventually connecting to an impostor listener and letting the
## upload retry loop below spin for hours.
waited=0
until (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; do
   kill -0 "${sshd_pid}" 2>/dev/null || fail "sshd exited before opening port ${port} (bind failed / port taken?)"
   sleep 0.3
   waited=$(( waited + 1 ))
   [ "${waited}" -lt 100 ] || fail "sshd did not open port ${port} within 30s"
done
exec 3>&- 2>/dev/null || true

## ssh transport wrapper (no spaces reach dm's unquoted ${rsync_opts}: rsync gets `-e <wrapper>`).
## -F /dev/null: ignore the user/system ssh_config entirely, so a stray ~/.ssh/config (e.g. a
## ProxyCommand/HostName for localhost on the runner) cannot redirect or hijack the connection --
## the test is hermetic, keyed only by the flags here.
cat > "${work}/ssh-wrap" <<EOF
#!/bin/bash
exec ssh -F /dev/null -i "${work}/id" -p "${port}" -o UserKnownHostsFile="${work}/known_hosts" -o StrictHostKeyChecking=accept-new -o BatchMode=yes "\$@"
EOF
chmod +x "${work}/ssh-wrap"

## --- a dummy image + the sidecars show_files() expects (test -f the image; the rest are rsync'd) ---
img_dir="${work}/img"
mkdir -p -- "${img_dir}"
img="${img_dir}/Test-Image.iso"
for ext in '' .asc .sig .torrent .torrent.asc .torrent.sig .sha512sums .sha512sums.asc .sha512sums.sig; do
   printf '%s\n' dummy > "${img}${ext}"
done

## remote dest (localhost == this host): a real dir rsync targets. --dry-run writes nothing into it.
dest="${work}/dest"
mkdir -p -- "${dest}"

## --- provide the few vars/functions the sourced functions read (main() -- hence pre/variables --
## does NOT run on source, so error()/colors/rsync_* come from here) ----------------------------
## shellcheck cannot see these are read by the sourced dm-upload-images functions at runtime.
# shellcheck disable=SC2034,SC2317
error() { printf '%s\n' "dm-upload-images-e2e: dm error(): $*" >&2; exit 1; }
# shellcheck disable=SC2034
cyan=""
# shellcheck disable=SC2034
reset=""
# shellcheck disable=SC2034
bold=""
# shellcheck disable=SC2034
red=""
# shellcheck disable=SC2034
rsync_cmd="rsync"
## -n: BOTH dm's --dry-run pass AND its subsequent "real" pass stay dry-run (nothing written).
## -e <wrapper>: ssh with the auto-gen key + the test port + a throwaway known_hosts.
# shellcheck disable=SC2034
rsync_opts="--archive -n -e ${work}/ssh-wrap"
# shellcheck disable=SC2034
build_upload_noninteractive="true"
# shellcheck disable=SC2034
dist_build_version="testver"
# shellcheck disable=SC2034
dist_build_installer_dist="false"
## The rsync target base + the DNS-probe list (dm appends /${dist_build_version}/).
# shellcheck disable=SC2034
dist_server_with_upload_location_item="$(id -un)@localhost:${dest}"
# shellcheck disable=SC2034
dist_build_upload_locations=("$(id -un)@localhost:${dest}")

## --- source the REAL dm-upload-images (source-able: defines functions, does NOT run main) ------
## Fail fast if the subject is NOT source-able (no was_executed guard): sourcing a version that
## auto-runs main would run parse-cmd AND install help-steps/pre's `trap exithandler EXIT`,
## clobbering our cleanup (leaking the sshd + key). The landed gitlink points at the source-able
## refactor; this guards a stale / un-bumped tree before we ever source it.
grep --quiet 'was_executed' "${subject}" || fail "dm-upload-images is not source-able (no was_executed guard) -- is the developer-meta-files gitlink bumped to the refactor?"
# shellcheck disable=SC1090
source "${subject}"
[ "$(type -t show_files)" = "function" ] || fail "sourcing dm-upload-images did not define show_files (not source-able?)"
[ "$(type -t upload_files)" = "function" ] || fail "sourcing dm-upload-images did not define upload_files"

## --- drive the REAL file-list build + the REAL rsync-over-ssh upload loop ----------------------
upload_file_list=()
show_files "${img}"
[ "${#upload_file_list[@]}" -ge 2 ] || fail "show_files built an empty/short upload_file_list"

## Pre-flight: confirm ssh key auth + the port work BEFORE upload_files. Otherwise a broken
## connection sends dm's upload_files into its 100x linear-backoff retry (~7h, far past the suite
## timeout) rather than failing here.
"${work}/ssh-wrap" "$(id -un)@localhost" true || fail "pre-flight ssh to localhost failed (key/sshd/port); not entering the upload retry loop"

rc=0
upload_files || rc=$?
[ "${rc}" -eq 0 ] || fail "upload_files (real rsync --dry-run over localhost ssh) returned ${rc}"

## --- assert it was a genuine dry-run: nothing actually transferred into the dest ---------------
written="$(find "${dest}" -type f | wc -l)"
[ "${written}" -eq 0 ] || fail "dry-run wrote ${written} file(s) into the dest -- expected none"

printf '%s\n' "PASS: real show_files + upload_files rsync-over-ssh to localhost with auto-gen key (dry-run, nothing written)"
printf '%s\n' "" "$(basename -- "$0"): 1 pass, 0 fail"
exit 0
