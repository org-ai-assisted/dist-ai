#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the REAL-GUI live-zoom lane (zoom_live_capture in comparison-capture.sh, wired as
## the `zoom-live` mode in the secure-terminal-shots wrapper + the -sandbox driver). Display-free:
## SOURCE the real comparison-capture.sh (source-safe via its was_executed guard) so
## zoom_live_capture is the CURRENT body with zero drift, stub its collaborators (the ST launch,
## window discovery, screenshot, and the `secure-terminal ctl` client), and drive it -- asserting
## it steps the zoom LIVE with one `ctl zoom --tab id:1 <pct>` per level against ONE instance (no
## relaunch) and grabs one shot per level. FAILS on the old harness (no zoom_live_capture at all),
## so it is a genuine regression, not a tautology.
##
## Subject: comparison-capture.sh + the two wrapper scripts, resolved from SECURE_TERMINAL_SHOTS_DIR
## / a checkout default / the installed path. Absent -> exit 1 (FATAL, R-220). Runs no real
## capture, spawns no process group -- pure logic, safe anywhere.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/comparison-capture.sh" \
   "${script_dir}/../secure-terminal-shots/comparison-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/comparison-capture.sh" \
   '/usr/share/secure-terminal-shots/comparison-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      subject="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' 'FATAL: comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi
shots_bin_dir="$(dirname -- "${subject}")/../../bin"
wrapper="${shots_bin_dir}/secure-terminal-shots"
sandbox_driver="${shots_bin_dir}/secure-terminal-shots-sandbox"

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3 (got '$1', want '$2')"
      fail=$(( fail + 1 ))
   fi
}

work="$(mktemp --directory)"
## Uniquely named: sourcing comparison-capture.sh below defines its OWN cleanup() (which reads
## run_marker, unset here), so a shared name would clobber this trap and error on exit.
zl_cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap zl_cleanup EXIT

## SOURCE the real script: source-safe (its was_executed guard runs no capture when sourced), so
## zoom_live_capture is the CURRENT body. check_runtime.bsh + lib-capture.sh are REQUIRED tooling;
## a genuine absence hard-fails the source, the correct loud FAILURE (not a skip).
# shellcheck source=../secure-terminal-shots/comparison-capture.sh
source "${subject}"
if ! declare -F zoom_live_capture >/dev/null 2>&1; then
   printf '%s\n' 'FAIL: zoom_live_capture not defined after sourcing comparison-capture.sh' >&2
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi

## A fake secure-terminal CLI: records every `ctl ...` invocation. zoom_live_capture calls it as
## `env VAR=val python3 "${st_bin}" ctl <args>`, so a python3 on PATH that logs its args (dropping
## the leading st_bin path) captures exactly the ctl subcommands issued.
ctl_log="${work}/ctl.log"
true > "${ctl_log}"
mkdir --parents -- "${work}/bin"
cat > "${work}/bin/python3" <<PY
#!/bin/bash
## args: <st_bin> ctl <subcmd...>; drop the st_bin path, log the rest.
shift || true
printf '%s\n' "\$*" >> "${ctl_log}"
case "\$1 \$2" in
   ## 'ctl ls' prints "<id>\t<title>" per tab -- the real client's format. A fresh single-tab
   ## instance numbers from 0, so zoom_live_capture must parse id 0 and target it (not a hardcode).
   'ctl ls') printf '0\tmain\n' ;;
   ## 'ctl zoom ...' prints the resulting zoom (the real client does); make it deterministic.
   'ctl zoom') printf '%s\n' "\${5:-100}" ;;
esac
exit 0
PY
chmod +x "${work}/bin/python3"
export PATH="${work}/bin:${PATH}"

## sudo: the privileged remote_control drop-in write must not need real root in the test. Record
## the attempt, succeed. (tee is fed on stdin; drain it so the pipe does not SIGPIPE.)
sudo() {
   case "${1:-}" in
      tee)
         cat > /dev/null
         ;;
      *)
         true
         ;;
   esac
   return 0
}

## Stub the GUI/capture collaborators so no display / process is needed.
capture_log="${work}/capture.log"
true > "${capture_log}"
shots_spawn_session() { : ; }           ## no real launch
shots_watchdog_start() { printf '%s' '0'; }
shots_watchdog_cancel() { : ; }
shots_reap_group() { : ; }
find_window() { printf '%s' '12345'; }  ## a non-empty window id
wait_window_ready() { : ; }
inject() { : ; }
st_wait_render_settled() { : ; }
capture_settled() { printf '%s\n' "$(basename -- "$1")" >> "${capture_log}"; }

## The globals zoom_live_capture reads (normally set by the main flow above the source boundary).
runtime_dir="${work}/rt"; mkdir --parents -- "${runtime_dir}"
export HOME="${work}/home"; mkdir --parents -- "${HOME}"
printf '%s\n' 'board' > "${HOME}/tui-showcase.payload"
out="${work}/shots"; mkdir --parents -- "${out}"
xwl_display=':99'
st_bin="${work}/fake-st"; true > "${st_bin}"
st_pkg="${work}/pkg"
SHOT_SCALE=1
SHOT_DEADLINE=90
zoom_live_rc_dropin=''
FRAME_TOP=26

## Drive the live-zoom loop over three levels (incl. a clamp-boundary value).
zoom_live_capture 50 150 400 >/dev/null 2>&1 || true

## The tab id is DISCOVERED from `ctl ls` (id 0 here), never hardcoded: assert exactly one live
## `ctl zoom --tab id:0 <level>` per level, on the SAME instance (no relaunch).
n="$(grep --count --fixed-strings -- 'ctl ls' "${ctl_log}" || true)"
check "${n}" '1' 'zoom-live discovers the tab id via a single ctl ls (not a hardcoded id)'
for lvl in 50 150 400; do
   n="$(grep --count --fixed-strings -- "ctl zoom --tab id:0 ${lvl}" "${ctl_log}" || true)"
   check "${n}" '1' "zoom-live issues exactly one live 'ctl zoom --tab id:0 ${lvl}'"
done
## Exactly one shot per level, named zoom-live-<zero-padded-pct>.png.
for f in zoom-live-050.png zoom-live-150.png zoom-live-400.png; do
   n="$(grep --count --fixed-strings -- "${f}" "${capture_log}" || true)"
   check "${n}" '1' "zoom-live captures one real-GUI shot ${f}"
done
## The privileged remote_control drop-in is targeted (PRIVILEGED_ONLY: no user-config path exists).
check "${zoom_live_rc_dropin}" '/usr/local/etc/secure-terminal.d/99-zoom-live-rc.conf' \
   'zoom-live enables remote_control via the /usr/local/etc privileged drop-in'

## Wrapper + sandbox-driver register the zoom-live lane (load-bearing dispatch lines, not comments).
[ -f "${wrapper}" ] || { printf '%s\n' "FATAL: wrapper not found at ${wrapper}" >&2; exit 1; }
[ -f "${sandbox_driver}" ] || { printf '%s\n' "FATAL: sandbox driver not found at ${sandbox_driver}" >&2; exit 1; }
if grep --quiet --fixed-strings -- "= 'zoom-live' ]" "${wrapper}" \
      && grep --quiet --fixed-strings -- "\${mode}\" = 'zoom-live'" "${wrapper}"; then
   check '0' '0' "secure-terminal-shots wrapper dispatches the zoom-live mode"
else
   check '1' '0' "secure-terminal-shots wrapper dispatches the zoom-live mode"
fi
if grep --quiet --fixed-strings -- 'comparison|zoom|zoom-live)' "${sandbox_driver}"; then
   check '0' '0' "secure-terminal-shots-sandbox accepts the zoom-live lane"
else
   check '1' '0' "secure-terminal-shots-sandbox accepts the zoom-live lane"
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' 'OK: zoom-live real-GUI live-zoom lane is wired'
