#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## loop_teardown_verify (help-steps/misc-helpers.bsh) is the shared teardown-
## verification primitive for the raw-image build: help-steps/unmount-raw and the
## mount-test self-test in build-steps.d/1100_sanity-tests both call it after
## 'kpartx -d' to release and verify the loop devices backing an image.
##
## REGRESSION: building a non-Qubes image inside a Qubes/Xen build VM (and inside
## docker) aborted with a benign "teardown did not release cleanly" error. In
## those environments 'kpartx -d' reports a partition map "in use. Not removing"
## and leaves the backing loop device attached; the previous code did a ONE-SHOT
## 'losetup --associated' check immediately after and treated the still-attached
## loop as a fatal failure. Its intended rescue -- an explicit per-device
## 'losetup -d -- <dev>' -- was itself broken: util-linux's detach mode parses the
## '--' AS the device ("losetup: /dev/--: detach failed"), so the detach silently
## no-opped under '|| true' and the loop stayed attached.
##
## REGRESSION 2: the maps-before-detach gate that fixed the orphan then broke the
## build itself. 'kpartx -d' can leave a ${base}pN map behind -- either a kpartx FALSE
## positive (it false-reports "in use" though the REAL open count is 0), or a PERSISTENT
## open count (the GPT "Linux root x86-64" auto-discovery partition auto-opened by the
## host with no removable holder, which does not clear). The gate alone, and the later
## 'dmsetup remove --retry' recovery, both FAIL the persistent case ('--retry' cannot
## remove an open map). The robust fix adds 'dmsetup remove --force': it cannot delete an
## open map but loads the 'error' target, dropping the map's loop reference, so the loop
## detaches without orphaning; detach is gated on every map being gone OR error-target'd.
##
## loop_teardown_verify must:
##   1. release a loop that an explicit 'losetup --detach <dev>' (NO '--') frees,
##      returning 0 (the benign Qubes/docker false positive);
##   2. release a loop that only clears on a later poll (udev/kernel async), via
##      its bounded re-poll, returning 0 -- WITHOUT depending on udev firing;
##   3. still return NON-ZERO for a genuinely stuck loop that remains associated
##      after every explicit-detach attempt (no masking of a real failure);
##   4. return 0 and attempt no detach when nothing is associated;
##   5. clear a kpartx false positive -- a ${base}pN map with open count 0 -- via
##      'dmsetup remove --retry', then detach and return 0;
##   6. recover a PERSISTENT open count -- 'dmsetup remove --force' loads the error
##      target, then detach the loop and return 0;
##   7. NEVER detach under a map that is still LIVE (no "Open count:1" orphan): if
##      --force cannot neutralize it, leave the loop attached and return NON-ZERO;
##   8. NEVER remove or gate on a coincidentally-named FOREIGN map (a ${base}pN map backed
##      by a different device, not this loop): it is identified by 'dmsetup deps' blkdevname.
##
## The real function is SOURCED. 'losetup'/'kpartx'/'dmsetup'/'findmnt'/'udevadm'/'sleep'
## are stubbed so the test needs no root and no real loop devices; SUDO_TO_ROOT is
## emptied so the stub bash functions (not external binaries) are what it calls.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

lib="${dm_checkout}/help-steps/misc-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

## Empty so '${SUDO_TO_ROOT} losetup ...' resolves the stub bash functions below
## rather than dispatching through 'sudo'/'env' to the real binaries.
# shellcheck disable=SC2034  # read by the sourced loop_teardown_verify, not directly here
SUDO_TO_ROOT=""

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## --- stubs -----------------------------------------------------------------
## Stub state lives in FILES, not shell variables. loop_teardown_verify reads
## 'losetup --associated' inside a command substitution '$(...)' (a subshell), and
## a correct implementation may iterate the device list in a subshell too -- a
## here-string 'while read' loop does not fork, but a 'printf ... | while read'
## pipe does. A shell-variable stub would lose its mutations across that boundary
## and FALSELY fail a correct pipe-based implementation, so the test would mislead.
## File-backed state survives any subshell, so this asserts on OBSERVABLE behavior
## (was a detach issued, for which device, did the device get released), never on
## the function's internal iteration construct.
##
## stub_* flags are read-only in the stub, so they are safely inherited into any
## subshell the function spawns.
stub_detach_releases=0   ## 1: a 'losetup -d'/'--detach' call clears the association (benign, no maps)
stub_clear_after_polls=0 ## >0: report empty once --associated has been polled N times
stub_assoc_rc=0          ## exit code 'losetup --associated' returns (non-zero = command itself failed)
stub_uses_maps=0         ## 1: the per-map model (below) governs when a detach frees the loop

state_dir="$(mktemp --directory)"
assoc_file="${state_dir}/assoc"               ## device 'losetup --associated' reports ("" = none)
detach_count_file="${state_dir}/detach_count" ## times a detach was issued
detach_last_file="${state_dir}/detach_last"   ## last device a detach saw
poll_file="${state_dir}/poll"                 ## times --associated was polled
map_file="${state_dir}/map"                   ## space-separated present ${base}pN map names ("" = none)
mapcount_file="${state_dir}/mapcount"         ## the maps' TRUE device-mapper open count (uniform)
dmremove_file="${state_dir}/dmremove"         ## times 'dmsetup remove --retry' was issued
mapforce_file="${state_dir}/mapforce"         ## times 'dmsetup remove --force' was issued
marks_dir="${state_dir}/marks"                ## per-map markers: err_<map> (error target), ff_<map> (--force cannot neutralize)
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${state_dir}"; }
trap cleanup EXIT

reset_stubs() {
   stub_detach_releases=0
   stub_clear_after_polls=0
   stub_assoc_rc=0
   stub_uses_maps=0
   printf '%s' ""  > "${assoc_file}"
   printf '%s' "0" > "${detach_count_file}"
   printf '%s' ""  > "${detach_last_file}"
   printf '%s' "0" > "${poll_file}"
   printf '%s' ""  > "${map_file}"
   printf '%s' "0" > "${mapcount_file}"
   printf '%s' "0" > "${dmremove_file}"
   printf '%s' "0" > "${mapforce_file}"
   safe-rm --recursive --force -- "${marks_dir}"
   mkdir -p -- "${marks_dir}"
}

set_assoc()         { printf '%s' "$1" > "${assoc_file}"; }
detach_count()      { cat -- "${detach_count_file}"; }
detach_last()       { cat -- "${detach_last_file}"; }
set_maps()          { printf '%s' "${1}" > "${map_file}"; }     ## space-separated map names
set_mapcount()      { printf '%s' "${1}" > "${mapcount_file}"; }
add_forcefail_map() { touch -- "${marks_dir}/ff_${1}"; }        ## this map's --force cannot load the error target
set_mounted_map()   { touch -- "${marks_dir}/mnt_${1}"; }       ## findmnt reports this map mounted
set_ls_fails()      { touch -- "${marks_dir}/lsfail"; }         ## 'dmsetup ls' exits non-zero (unreadable listing)
set_table()         { printf '%s' "${2}" > "${marks_dir}/tbl_${1}"; }  ## override 'dmsetup table <map>' output
set_backing()       { printf '%s' "${2}" > "${marks_dir}/backing_${1}"; }  ## this map's backing block-device name (default loop7 = owned)
dmremove_count()    { cat -- "${dmremove_file}"; }
mapforce_count()    { cat -- "${mapforce_file}"; }

## A map's backing block-device name: an explicit backing_<map> marker, else loop7 (owned).
# shellcheck disable=SC2317
map_backing() { if [ -e "${marks_dir}/backing_${1}" ]; then cat -- "${marks_dir}/backing_${1}"; else printf '%s' "loop7"; fi; }

## Map helpers over the space-separated ${map_file} list + per-map markers in ${marks_dir}.
## (SC2013: the map list is space-separated words on one line, so word-splitting $(cat) is
## intended; SC2317: these are invoked indirectly, from the sourced loop_teardown_verify.)
# shellcheck disable=SC2317
map_present() {   ## ${1} present in the list?
   case " $(cat -- "${map_file}") " in *" ${1} "*) return 0 ;; *) return 1 ;; esac
}
# shellcheck disable=SC2317,SC2013
map_remove() {    ## drop ${1} from the list
   local m rest=""
   for m in $(cat -- "${map_file}"); do
      [ "${m}" = "${1}" ] || rest="${rest:+${rest} }${m}"
   done
   printf '%s' "${rest}" > "${map_file}"
}
# shellcheck disable=SC2317,SC2013
any_live_map() {  ## $1 = loop base name; true if a present map is non-error AND backed by THIS loop
   local m loop_base
   loop_base="${1:-}"
   for m in $(cat -- "${map_file}"); do
      [ -e "${marks_dir}/err_${m}" ] && continue       ## neutralized -> no longer holds the loop
      ## a foreign map (backed by a different device) never holds this loop
      [ -n "${loop_base}" ] && [ "$(map_backing "${m}")" != "${loop_base}" ] && continue
      return 0
   done
   return 1
}

## losetup stub. Dispatches on the first word:
##   --associated <img> --noheadings --output NAME  -> print the association (if any)
##   -d|--detach <dev>                              -> record + maybe release
## Both detach spellings are honored: util-linux accepts '-d' and '--detach'
## interchangeably, so the stub is not coupled to the one the function happens to use.
# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
losetup() {
   local poll_now assoc_now detach_base
   case "${1:-}" in
      --associated)
         poll_now="$(cat -- "${poll_file}")"
         poll_now=$(( poll_now + 1 ))
         printf '%s' "${poll_now}" > "${poll_file}"
         if [ "${stub_assoc_rc}" != "0" ]; then
            ## Simulate the COMMAND itself failing (sudo needs a password, losetup
            ## missing, permission denied) -- distinct from "nothing associated".
            return "${stub_assoc_rc}"
         fi
         assoc_now="$(cat -- "${assoc_file}")"
         if [ "${stub_clear_after_polls}" -gt 0 ] && [ "${poll_now}" -ge "${stub_clear_after_polls}" ]; then
            true "released by the time of this re-poll, report nothing"
         elif [ -n "${assoc_now}" ]; then
            printf '%s\n' "${assoc_now}"
         fi
         ;;
      -d|--detach)
         printf '%s' "$(( $(cat -- "${detach_count_file}") + 1 ))" > "${detach_count_file}"
         printf '%s' "${2:-}" > "${detach_last_file}"
         if [ "${stub_uses_maps}" = "1" ]; then
            ## map model: the loop frees ONLY when the CORRECT loop operand is detached AND no
            ## live (non-error) map BACKED BY IT remains. Detaching the wrong device, or while
            ## an owned live map remains, does not free it (on real dm that would orphan it). A
            ## foreign map (backed by a different device) does not hold this loop.
            detach_base="${2##*/}"
            if [ "${2:-}" = "$(cat -- "${assoc_file}")" ] && ! any_live_map "${detach_base}"; then
               printf '%s' "" > "${assoc_file}"
            fi
         elif [ "${stub_detach_releases}" = "1" ]; then
            printf '%s' "" > "${assoc_file}"
         fi
         ;;
      *)
         true "any other losetup invocation (e.g. --all) is a harmless no-op here"
         ;;
   esac
}

# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
kpartx() {
   true
}

## dmsetup stub -- PER MAP, honoring the device-name argument (a single global flag would let
## an implementation that mishandles one of several partition maps false-pass). Subcommands:
##   ls --noheadings        -> list every present ${base}pN map (nodes linger after --force);
##                             exits NON-ZERO if set_ls_fails (an unreadable listing: the
##                             function MUST fail closed, never read it as "no maps left")
##   table <map>            -> 'error' once THAT map was --force'd to the error target, else
##                             'linear' (live on the loop); set_table overrides it verbatim
##   remove [--retry] [-f|--force] <map>  -> flags in any order ('-f' == '--force'); honor the
##                             TRUE open count: remove a free map (open 0); for an open map,
##                             --force loads the error target (unless ff_<map>) and returns
##                             non-zero (busy), retry/plain cannot and return non-zero
## An unrecognized form FAILS CLOSED (non-zero), never a silent empty success.
## Isolates the test from real device-mapper state on the build host.
# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
dmsetup() {
   local open_count map arg have_retry have_force m backing
   case "${1:-}" in
      ls)
         [ -e "${marks_dir}/lsfail" ] && return 1
         # shellcheck disable=SC2013  # map list is space-separated words; word-split is intended
         for m in $(cat -- "${map_file}"); do printf '%s\n' "${m}"; done
         ;;
      deps)
         ## 'dmsetup deps --noheadings -o blkdevname <map>' -> the map's backing block-device
         ## name in the real "N dependencies  : (name)" format. Default loop7 (owned);
         ## set_backing overrides it (e.g. sda1 for a foreign map named like ours).
         map=""
         for arg in "$@"; do map="${arg}"; done   ## the map is the last arg (deps ... -o blkdevname <map>)
         if map_present "${map}"; then
            backing="$(map_backing "${map}")"
            printf '%s\n' "1 dependencies  : (${backing})"
         fi
         ;;
      table)
         map="${2:-}"
         if [ -e "${marks_dir}/tbl_${map}" ]; then
            cat -- "${marks_dir}/tbl_${map}"
         elif map_present "${map}"; then
            if [ -e "${marks_dir}/err_${map}" ]; then
               printf '%s\n' "0 16384 error"
            else
               printf '%s\n' "0 16384 linear 7:9 2048"
            fi
         fi
         ;;
      remove)
         shift
         have_retry=0
         have_force=0
         map=""
         for arg in "$@"; do
            case "${arg}" in
               --retry)
                  have_retry=1
                  ;;
               -f|--force)
                  have_force=1
                  ;;
               -*)
                  true "ignore any other flag"
                  ;;
               *)
                  map="${arg}"
                  ;;
            esac
         done
         if [ "${have_retry}" = "1" ]; then
            printf '%s' "$(( $(cat -- "${dmremove_file}") + 1 ))" > "${dmremove_file}"
         fi
         if [ "${have_force}" = "1" ]; then
            printf '%s' "$(( $(cat -- "${mapforce_file}") + 1 ))" > "${mapforce_file}"
         fi
         map_present "${map}" || return 0   ## already gone -> idempotent success
         open_count="$(cat -- "${mapcount_file}")"
         if [ "${open_count}" -le 0 ]; then
            map_remove "${map}"
            return 0
         fi
         ## open map: only --force can act, loading the error target unless this map is
         ## marked un-neutralizable; it still exits non-zero (busy). retry/plain: non-zero.
         if [ "${have_force}" = "1" ] && [ ! -e "${marks_dir}/ff_${map}" ]; then
            touch -- "${marks_dir}/err_${map}"
         fi
         return 1
         ;;
      *)
         ## FAIL-CLOSED: an unrecognized dmsetup form must not silently return empty success.
         ## The function gates detach on the QUERY path (ls/table), so a fabricated empty
         ## result would cause a detach under a live map. Refuse loudly instead.
         printf '%s\n' "dmsetup stub: unrecognized invocation: $*" >&2
         return 2
         ;;
   esac
}

## findmnt stub -- loop_teardown_verify's dm_map_mounted runs
## 'findmnt --noheadings --source /dev/mapper/<map>' before --force. Report mounted iff a
## mnt_<map> marker exists; otherwise not mounted. Stubbed so cases do not leak host state.
# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
findmnt() {
   local prev="" a map=""
   for a in "$@"; do
      [ "${prev}" = "--source" ] && map="${a##*/}"
      prev="${a}"
   done
   [ -n "${map}" ] && [ -e "${marks_dir}/mnt_${map}" ]
}

# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
udevadm() {
   true
}

## Make the bounded re-poll instant -- exercises the real retry code with no
## wall-clock cost.
# shellcheck disable=SC2317  # invoked indirectly, from the sourced loop_teardown_verify
sleep() {
   true
}

img="/path/to/image.raw"

## --- case 1: already clean -> return 0, no detach attempted -----------------
reset_stubs
set_assoc ""
if loop_teardown_verify "${img}" ; then
   if [ "$(detach_count)" = "0" ]; then
      pass "already clean: returns 0 without attempting a detach"
   else
      fail "already clean: detach attempted $(detach_count) time(s)"
   fi
else
   fail "already clean: expected return 0, got non-zero"
fi

## --- case 2: benign -- an explicit detach releases the loop -----------------
## (the Qubes/docker false positive: kpartx -d left it attached, losetup -d frees it)
reset_stubs
set_assoc "/dev/loop7"
stub_detach_releases=1
if loop_teardown_verify "${img}" ; then
   if [ "$(detach_count)" -ge "1" ] && [ "$(detach_last)" = "/dev/loop7" ]; then
      pass "benign (detach frees it): returns 0 after an explicit losetup detach"
   else
      fail "benign: detach_count=$(detach_count) detach_last='$(detach_last)'"
   fi
else
   fail "benign (detach frees it): expected return 0, got non-zero (one-shot regression)"
fi

## --- case 3: benign -- clears only on a later poll (udev/kernel async) -------
## Proves the bounded re-poll absorbs a transient reference without relying on
## udev firing (detach itself does NOT clear it here).
reset_stubs
set_assoc "/dev/loop7"
stub_detach_releases=0
stub_clear_after_polls=2
if loop_teardown_verify "${img}" ; then
   pass "benign (clears on re-poll): returns 0 via the bounded retry"
else
   fail "benign (clears on re-poll): expected return 0, got non-zero"
fi

## --- case 4: genuinely stuck -> return NON-ZERO, no masking -----------------
## The loop stays associated no matter how many times it is detached/re-polled.
reset_stubs
set_assoc "/dev/loop7"
stub_detach_releases=0
stub_clear_after_polls=0
if loop_teardown_verify "${img}" ; then
   fail "genuine stuck: expected non-zero return, got 0 (fix would MASK a real failure)"
else
   if [ "$(detach_count)" -ge "1" ]; then
      pass "genuine stuck: returns non-zero after attempting explicit detach (no mask)"
   else
      fail "genuine stuck: returned non-zero but never attempted a detach"
   fi
fi

## --- case 5: empty image argument -> return non-zero (programming guard) -----
reset_stubs
if loop_teardown_verify "" ; then
   fail "empty image: expected non-zero return, got 0"
else
   pass "empty image: returns non-zero"
fi

## --- case 6: 'losetup --associated' COMMAND fails -> return non-zero ---------
## A failure of the verification command itself (sudo needs a password, losetup
## missing, permission denied) is NOT "nothing associated" and must NOT be
## swallowed into a false "clean". The old one-shot code did
## 'out="$(... || true)"; [ -z "$out" ]', which returned 0 (success) here.
reset_stubs
set_assoc ""
stub_assoc_rc=1
if loop_teardown_verify "${img}" ; then
   fail "losetup --associated fails: expected non-zero return, got 0 (fail-open regression)"
else
   pass "losetup --associated fails: returns non-zero (no false clean)"
fi

## --- case 7: kpartx false positive -- map left though TRUE open count is 0 -------
## kpartx -d refused to remove the map ("in use. Not removing") yet its real open
## count is 0. 'dmsetup remove --retry' clears it, then the loop detaches -> return 0.
## RED against the gate-only predecessor (no dmsetup remove), which looped and failed.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 0
if loop_teardown_verify "${img}" ; then
   if [ "$(dmremove_count)" -ge "1" ] && [ "$(detach_count)" -ge "1" ]; then
      pass "kpartx false positive (open 0): --retry clears it, then detaches, returns 0"
   else
      fail "kpartx false positive: dmremove_count=$(dmremove_count) detach_count=$(detach_count)"
   fi
else
   fail "kpartx false positive (open 0): expected return 0, got non-zero"
fi

## --- case 8: PERSISTENT open count -> --force error target, detach, return 0 -----
## The map's open count stays > 0 (the GPT root-auto partition, no removable holder), so
## 'dmsetup remove --retry' cannot remove it. 'dmsetup remove --force' loads the error
## target, dropping the map's loop reference, so the loop detaches and the function
## returns 0. --retry MUST be tried before --force (no needless error-targeting). RED
## against the retry-only predecessor (0f459d4c), which never forced.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 1
if loop_teardown_verify "${img}" ; then
   if [ "$(dmremove_count)" -ge "1" ] && [ "$(mapforce_count)" -ge "1" ] && [ "$(detach_count)" -ge "1" ]; then
      pass "persistent open count: --retry first, then --force error target, then detaches, returns 0"
   else
      fail "persistent open count: dmremove=$(dmremove_count) mapforce=$(mapforce_count) detach=$(detach_count)"
   fi
else
   fail "persistent open count: expected return 0, got non-zero (recovery regressed to retry-only)"
fi

## --- case 9: NO-ORPHAN backstop -- --force cannot neutralize the map -------------
## Defensive: if 'dmsetup remove --force' fails to load the error target, the map stays
## LIVE on the loop. The function must then NEVER detach (a detach would orphan it,
## "Open count:1") and must fail loudly instead.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 1
add_forcefail_map "loop7p1"
if loop_teardown_verify "${img}" ; then
   fail "force cannot neutralize: expected non-zero return, got 0 (would mask / orphan)"
else
   if [ "$(detach_count)" = "0" ]; then
      pass "force cannot neutralize: never detaches under a live map (no orphan), returns non-zero"
   else
      fail "force cannot neutralize: detached under a live map $(detach_count) time(s) -- orphan risk"
   fi
fi

## --- case 10: MULTI-MAP -- only the loop's maps that neutralize may free it ------
## Two maps on the loop; only loop7p1 can be forced to the error target, loop7p2 cannot.
## loop7p2 stays LIVE, so the loop must NOT be detached (that would orphan loop7p2). Guards
## against an implementation that detaches once SOME (not every) map is neutralized.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1 loop7p2"
set_mapcount 1
add_forcefail_map "loop7p2"
if loop_teardown_verify "${img}" ; then
   fail "multi-map one still live: expected non-zero return, got 0 (orphaned loop7p2)"
else
   if [ "$(detach_count)" = "0" ]; then
      pass "multi-map one still live: never detaches while loop7p2 is live (no orphan), returns non-zero"
   else
      fail "multi-map one still live: detached with loop7p2 live $(detach_count) time(s) -- orphan"
   fi
fi

## --- case 11: FAIL-CLOSED -- 'dmsetup ls' fails while a map is present -----------
## An unreadable listing must NEVER be read as "no maps left" (the old '| grep || true'
## swallowed its exit status). With a map present but ls failing, the function must NOT
## detach -- it keeps the loop attached and fails loudly after its retries.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 0           ## retry WOULD remove it if the listing were readable
set_ls_fails
if loop_teardown_verify "${img}" ; then
   fail "dmsetup ls fails: expected non-zero return, got 0 (fail-open: detached on an unreadable listing)"
else
   if [ "$(detach_count)" = "0" ]; then
      pass "dmsetup ls fails: fail-closed -- never detaches on an unreadable listing, returns non-zero"
   else
      fail "dmsetup ls fails: detached $(detach_count) time(s) despite an unreadable listing -- orphan risk"
   fi
fi

## --- case 12: REFUSE --force on a MOUNTED map -----------------------------------
## --force loads the error target, which would make a mounted filesystem's I/O fail
## (corruption). The function must refuse to force a mounted map, leave the loop attached,
## and fail loudly -- never corrupt a live filesystem and claim success.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 1
set_mounted_map "loop7p1"
if loop_teardown_verify "${img}" ; then
   fail "mounted map: expected non-zero return, got 0 (forced/corrupted a mounted fs)"
else
   if [ "$(mapforce_count)" = "0" ] && [ "$(detach_count)" = "0" ]; then
      pass "mounted map: refuses --force and never detaches (no corruption, no orphan), returns non-zero"
   else
      fail "mounted map: mapforce=$(mapforce_count) detach=$(detach_count) -- forced or detached a mounted map"
   fi
fi

## --- case 13: multi-segment table -- EVERY segment must be the error target -----
## A map whose table has an error segment AND a still-live linear segment is NOT fully
## neutralized (the live segment still references the loop). The function must read ALL
## segments, not just the first, and keep the loop attached. Guards against an awk
## 'print $3; exit' that only inspects the first line.
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 1
set_table "loop7p1" "0 2048 error
2048 14336 linear 7:9 4096"
if loop_teardown_verify "${img}" ; then
   fail "multi-segment table: expected non-zero return, got 0 (detached under a live segment)"
else
   if [ "$(detach_count)" = "0" ]; then
      pass "multi-segment table: a live segment keeps the loop attached (no orphan), returns non-zero"
   else
      fail "multi-segment table: detached $(detach_count) time(s) under a live segment -- orphan risk"
   fi
fi

## --- case 14: OWNERSHIP -- a coincidentally-named FOREIGN map is never removed ---------
## A pre-existing unmounted dm map named loop7p1 but backed by /dev/sda1, open count 0.
## It is NOT ours (backed by sda1, not loop7): dm_partition_maps must skip it, so it is never removed and
## never gates our detach -- the loop (no OWNED maps) detaches and the foreign map is left
## intact. Guards against the name-match-vs-loop-ownership gap (would delete /dev/sda1's map).
reset_stubs
stub_uses_maps=1
set_assoc "/dev/loop7"
set_maps "loop7p1"
set_mapcount 0                 ## open 0 -> --retry WOULD delete it if it were treated as ours
set_backing "loop7p1" "sda1"   ## backed by /dev/sda1, NOT loop7
if loop_teardown_verify "${img}" ; then
   if [ "$(dmremove_count)" = "0" ] && [ "$(mapforce_count)" = "0" ] && map_present "loop7p1"; then
      pass "foreign map (backed by sda1): never removed (not ours), loop still detaches, returns 0"
   else
      fail "foreign map: dmremove=$(dmremove_count) mapforce=$(mapforce_count) present=$(map_present loop7p1 && printf '%s' yes || printf '%s' no)"
   fi
else
   fail "foreign map: expected return 0 (loop detaches, foreign map untouched), got non-zero"
fi

summary_line="===== loop_teardown_verify: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
