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
check_nonzero() {  ## $1=rc $2=label -- passes iff rc is nonzero
   if [ "$1" -ne 0 ]; then
      check '0' '0' "$2"
   else
      check '1' '0' "$2"
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
## args: <st_bin> ctl <subcmd...>; drop the st_bin path, log the rest. ZL_STUB_MODE drives the
## failure scenarios: 'no-tab' makes 'ctl ls' return nothing; 'zoom-fail' makes every 'ctl zoom'
## exit nonzero; anything else is the happy path.
shift || true
printf '%s\n' "\$*" >> "${ctl_log}"
zl_mode="\${ZL_STUB_MODE:-ok}"
case "\$1 \$2" in
   'ctl ls')
      ## real client prints "<id>\t<title>" per tab; a fresh single-tab instance numbers from 0,
      ## so zoom_live_capture must parse id 0 (not a hardcode). 'no-tab' returns none.
      case "\${zl_mode}" in
         no-tab)
            true
            ;;
         *)
            printf '0\tmain\n'
            ;;
      esac
      ;;
   'ctl zoom')
      ## real client prints the resulting zoom; 'zoom-fail' fails instead.
      case "\${zl_mode}" in
         zoom-fail)
            exit 1
            ;;
         *)
            printf '%s\n' "\${5:-100}"
            ;;
      esac
      ;;
esac
exit 0
PY
chmod +x "${work}/bin/python3"
export PATH="${work}/bin:${PATH}"

## sudo: the privileged drop-in work must not need real root in the test. mkdir/other succeed as a
## no-op; 'mktemp' makes a UNIQUE zoom-live-rc.*.conf under the test work dir (never touches the
## real /usr/local/etc); 'tee' writes to the target file; 'safe-rm' really removes -- unless
## ZL_SUDO_FAIL is set, which forces it to fail (drives the cleanup-warns-on-failure assertion).
sudo() {
   case "${1:-}" in
      tee)
         ## Faithfully consume stdin and succeed regardless of the target path -- only the drop-in
         ## PATH is asserted, never its content, so the write never needs real /usr/local/etc access.
         cat >> "${work}/tee.out"
         ;;
      mktemp)
         mktemp -- "${work}/zoom-live-rc.XXXXXX.conf"
         ;;
      safe-rm)
         if [ -n "${ZL_SUDO_FAIL:-}" ]; then
            return 1
         fi
         shift
         safe-rm "$@"
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
## The privileged remote_control drop-in is a UNIQUE root-owned path, NOT a fixed name (a fixed
## name would truncate an admin file or a concurrent run's drop-in). It matches zoom-live-rc.*.conf.
case "${zoom_live_rc_dropin}" in
   */zoom-live-rc.*.conf)
      check '0' '0' 'zoom-live drop-in is a UNIQUE zoom-live-rc.*.conf path'
      ;;
   *)
      check '1' '0' 'zoom-live drop-in is a UNIQUE zoom-live-rc.*.conf path'
      ;;
esac
if [ "${zoom_live_rc_dropin}" = '/usr/local/etc/secure-terminal.d/99-zoom-live-rc.conf' ]; then
   check '1' '0' 'zoom-live drop-in is NOT the old fixed 99-zoom-live-rc.conf name'
else
   check '0' '0' 'zoom-live drop-in is NOT the old fixed 99-zoom-live-rc.conf name'
fi

## (ii) cleanup's drop-in removal is LOUD on failure: it NAMES the leaked path and does not swallow
## the error (a leaked drop-in keeps remote_control enabled system-wide).
zoom_live_rc_dropin="${work}/leaked-dropin.conf"
warn_out="$(ZL_SUDO_FAIL=1 zoom_live_remove_dropin 2>&1 1>/dev/null || true)"
case "${warn_out}" in
   *'could not remove privileged remote_control drop-in'*"${work}/leaked-dropin.conf"*)
      check '0' '0' 'zoom-live cleanup warns loudly and names the leaked drop-in on removal failure'
      ;;
   *)
      check '1' '0' 'zoom-live cleanup warns loudly and names the leaked drop-in on removal failure'
      ;;
esac
rc=0
ZL_SUDO_FAIL=1 zoom_live_remove_dropin >/dev/null 2>&1 || rc="$?"
check_nonzero "${rc}" 'zoom-live cleanup returns nonzero when the drop-in removal fails'

## (i) A failed sweep must RETURN NONZERO -- never false-green while claiming to verify a live zoom.
## no-tab: `ctl ls` yields no tab (remote_control unreachable), so no shot reflects a live zoom.
true > "${ctl_log}"
true > "${capture_log}"
rc=0
ZL_STUB_MODE=no-tab zoom_live_capture 50 100 >/dev/null 2>&1 || rc="$?"
check_nonzero "${rc}" 'zoom_live_capture returns nonzero when ctl ls yields no tab'
## zoom-fail: every `ctl zoom` fails.
true > "${ctl_log}"
true > "${capture_log}"
rc=0
ZL_STUB_MODE=zoom-fail zoom_live_capture 50 100 >/dev/null 2>&1 || rc="$?"
check_nonzero "${rc}" 'zoom_live_capture returns nonzero when every ctl zoom fails'

## (iii) A non-numeric level is SKIPPED (never crashes `$(( 10#level ))` into a zoom-live-.png that
## silently overwrites): no ctl zoom for it, no zoom-live-.png, and the numeric levels still shoot.
true > "${ctl_log}"
true > "${capture_log}"
safe-rm --recursive --force -- "${out}" 2>/dev/null || true
mkdir --parents -- "${out}"
zoom_live_capture 50 abc 100 >/dev/null 2>&1 || true
n="$(grep --count --fixed-strings -- 'ctl zoom --tab id:0 abc' "${ctl_log}" || true)"
check "${n}" '0' 'zoom-live issues no ctl zoom for a non-numeric level'
n="$(grep --count --fixed-strings -- 'zoom-live-.png' "${capture_log}" || true)"
check "${n}" '0' 'zoom-live never writes the collapsed zoom-live-.png for a non-numeric level'
for f in zoom-live-050.png zoom-live-100.png; do
   n="$(grep --count --fixed-strings -- "${f}" "${capture_log}" || true)"
   check "${n}" '1' "zoom-live still captures numeric level ${f} alongside a skipped one"
done

## (iv) Levels do not glob: a '*' level reaches the function as a LITERAL token (array-carried), so
## it is never expanded against the cwd. If it globbed, the cwd filenames would surface in the
## function's own processing (here as per-level "skipping non-numeric" warnings); assert they don't.
true > "${ctl_log}"
true > "${capture_log}"
safe-rm --recursive --force -- "${out}" 2>/dev/null || true
mkdir --parents -- "${out}"
true > "${HOME}/globbait-a"
true > "${HOME}/globbait-b"
cd -- "${HOME}"
glob_out="$(zoom_live_capture '*' 2>&1 || true)"
cd -- "${work}"
n="$(printf '%s\n' "${glob_out}" | grep --count --fixed-strings -- 'globbait' || true)"
check "${n}" '0' 'zoom-live does not glob a * level against the cwd (no cwd filename enters processing)'
## The literal '*' is the token actually seen (skipped as non-numeric), proving it was not expanded.
n="$(printf '%s\n' "${glob_out}" | grep --count --fixed-strings -- "non-numeric zoom level '*'" || true)"
check "${n}" '1' 'zoom-live sees the literal * level (not a glob expansion)'

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
