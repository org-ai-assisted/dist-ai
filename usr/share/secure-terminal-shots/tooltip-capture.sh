#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Capture secure-terminal's InfoTip risk-tooltip on a REAL headless Wayland compositor
## (labwc + grim, via wl-headless-lib.bash), trimmed to the card. Mirrors
## comparison-capture.sh's bringup/capture idiom; tooltip-shot.py SHOWS the tip, this
## orchestrates the compositor + capture. The `secure-terminal-shots` wrapper converts the
## PNG to webp afterwards.
##
## Usage: tooltip-capture.sh OUTPUT.png [dark|light]
## Needs PYTHONPATH pointing at the secure-terminal package (the wrapper exports it).

here="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
## Single source for the labwc-headless bringup + grim trim-to-window. A no-strict fragment,
## so it is sourced BEFORE the strict-mode block (in main) rather than under it.
# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${here}/../dist-ai-tests-common/wl-headless-lib.bash"
## check_runtime.bsh provides was_executed, so a dist-ai test may SOURCE this for its
## functions without running the capture. Absent -> fail loud.
if [ ! -r /usr/libexec/helper-scripts/check_runtime.bsh ]; then
   printf '%s\n' 'tooltip-capture: helper-scripts check_runtime.bsh not found' >&2
   exit 1
fi
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/check_runtime.bsh

## Strict-mode + locale pin, guarded so a dist-ai test may SOURCE this without the
## strict block (or a capture run) leaking into the test shell (R-010a). Enabled AFTER
## the no-strict wl-headless-lib source above.
if was_executed "${BASH_SOURCE[0]}"; then
   set -o errexit
   set -o nounset
   set -o pipefail
   set -o errtrace
   shopt -s inherit_errexit
   shopt -s shift_verbose
   export LC_ALL=C
fi

runtime_dir=''
helper_pid=''

cleanup() {
   if [ -n "${helper_pid}" ]; then
      kill "${helper_pid}" 2>/dev/null || true
   fi
   wl_headless_stop 2>/dev/null || true
   if [ -n "${runtime_dir}" ]; then
      safe-rm --recursive --force -- "${runtime_dir}" 2>/dev/null || true
   fi
}

main() {
   local out="${1:-}" theme="${2:-dark}" probe mapped=0 _i
   if [ -z "${out}" ]; then
      printf '%s\n' 'tooltip-capture: no output file' >&2
      return 2
   fi

   trap cleanup EXIT
   runtime_dir="$(mktemp --directory)"

   if ! wl_headless_start --runtime "${runtime_dir}" --output-scale "${SHOT_SCALE:-2}"; then
      printf '%s\n' 'tooltip-capture: labwc bringup failed' >&2
      return 1
   fi

   ## Force the wayland QPA: a caller that also runs the offscreen gens exports
   ## QT_QPA_PLATFORM=offscreen, which would render the tip offscreen (no compositor window).
   export QT_QPA_PLATFORM=wayland
   ## Run the +x show helper via its own shebang (keeps its -Bsu flags; R-193).
   "${here}/tooltip-shot.py" "${theme}" 100 &
   helper_pid="$!"

   ## capture_settled takes its FIRST frame as the baseline and SKIPS its retry loop if that
   ## frame is degenerate (nothing mapped yet), so wait for the tip to actually map first.
   probe="$(mktemp --suffix=.png)"
   for _i in $(seq 1 40); do
      if wl_headless_capture_window "${probe}" 2>/dev/null; then
         mapped=1
         break
      fi
      sleep 0.25
   done
   safe-rm --force -- "${probe}" 2>/dev/null || true
   if [ "${mapped}" != 1 ]; then
      printf '%s\n' 'tooltip-capture: tip never mapped' >&2
      return 1
   fi

   ## Settle on two matching trimmed frames (a static tip settles fast); max-diff 2 tolerates
   ## sub-pixel AA jitter. capture_settled trims to the single window on the black output.
   if ! wl_headless_capture_settled "${out}" 25 2; then
      printf '%s\n' 'tooltip-capture: capture did not settle' >&2
      return 1
   fi
   printf '%s\n' "tooltip-capture: wrote ${out}"
}

if was_executed "${BASH_SOURCE[0]}"; then
   main "$@"
fi
