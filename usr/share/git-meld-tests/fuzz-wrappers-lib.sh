#!/bin/bash
## Fuzzer for the git-review-difftool / git-review-mergetool FAIL-CLOSED
## invariant: a FATAL blob (undecodable / non-UTF-8, unicode-show rc >= 2) or a
## BINARY (NUL) blob must NEVER be handed to the viewer. Random adversarial blobs,
## a stub viewer, direct per-file (difftool) and per-conflict (mergetool)
## invocation of the wrappers. Deterministic given a seed.
## Usage: fuzz-wrappers-lib.sh <bindir> <iterations> <seed>
## style-ok: no-safe-rm (rm only touches throwaway mktemp workspaces)
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

bindir="$1"
iters="${2:-200}"
seed="${3:-1}"
difftool_bin="${bindir}/git-review-difftool"
mergetool_bin="${bindir}/git-review-mergetool"
if [ ! -x "${difftool_bin}" ] || [ ! -x "${mergetool_bin}" ]; then
   ## 77 == SKIP (target not found), per the dist-ai-tests-all convention.
   printf '%s\n' "fuzz-wrappers-lib: git-review-difftool/mergetool not found under '${bindir}'; skipping." >&2
   exit 77
fi

work="$( mktemp --directory )"
# shellcheck disable=SC2317
cleanup() { rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Stub viewers record any invocation; the wrapper must never reach them for a
## fatal/binary blob.
stubdir="${work}/bin"
mkdir --parents -- "${stubdir}"
gui_log="${work}/gui.log"
for gui in meld kdiff3; do
   printf '#!/bin/bash\nprintf "OPENED\\n" >> "%s"\nexit 0\n' "${gui_log}" > "${stubdir}/${gui}"
   chmod +x "${stubdir}/${gui}"
done
export PATH="${stubdir}:${PATH}"

RANDOM="${seed}"
fails=0

## Random safe-or-adversarial blob (mirrors the driver fuzzer's mix, plus an
## explicitly undecodable case so fatal blobs actually occur).
rand_blob () {
   local kind=$(( RANDOM % 7 ))
   case "${kind}" in
      0) printf 'line %s\ncode %s\n' "${RANDOM}" "${RANDOM}" ;;
      1) printf 'a\x00b NUL %s\n' "${RANDOM}" ;;                                  ## binary
      2) printf 'x # \xe2\x80\xae\xe2\x81\xa6hidden\xe2\x81\xa9 %s\n' "${RANDOM}" ;; ## bidi (non-fatal)
      3) printf 'plain ascii %s\n' "${RANDOM}" ;;
      4) head -c $(( (RANDOM % 3000) + 1 )) /dev/zero | tr '\0' 'A'; printf '\n' ;; ## long line
      5) printf '\xef\xbb\xbfbom %s\n' "${RANDOM}" ;;
      6) printf 'bad \xff\xfe undecodable %s\n' "${RANDOM}" ;;                     ## fatal (rc>=2)
   esac
}

## FATAL == unicode-show rc >= 2 (undecodable / non-UTF-8).
is_fatal () {
   local rc=0
   UNICODE_SHOW_ALLOW_MISSING_FINAL_NEWLINE=1 NO_COLOR=1 unicode-show "$1" >/dev/null 2>&1 || rc=$?
   [ "${rc}" -ge 2 ]
}

## BINARY == contains a NUL (same test the wrappers use).
is_binary () {
   LC_ALL=C grep --quiet --text --perl-regexp '\x00' -- "$1" 2>/dev/null
}

## True if any of the given files is hostile (fatal or binary).
any_hostile () {
   local f
   for f in "$@"; do
      if is_fatal "${f}" || is_binary "${f}"; then
         return 0
      fi
   done
   return 1
}

printf '== git-review wrapper fuzz: %s iters, seed %s, %s ==\n' "${iters}" "${seed}" "${bindir}"
i=0
while [ "${i}" -lt "${iters}" ]; do
   i=$(( i + 1 ))
   a="${work}/a"
   b="${work}/b"
   c="${work}/c"
   m="${work}/m"
   rand_blob > "${a}"
   rand_blob > "${b}"
   rand_blob > "${c}"
   rand_blob > "${m}"

   ## difftool: a fatal/binary $LOCAL or $REMOTE must never open the viewer.
   true > "${gui_log}"
   "${difftool_bin}" meld "${a}" "${b}" >/dev/null 2>&1 || true
   if [ -s "${gui_log}" ] && any_hostile "${a}" "${b}"; then
      fails=$(( fails + 1 ))
      printf 'FAIL iter=%s: difftool opened the viewer on a fatal/binary blob\n' "${i}" >&2
   fi

   ## mergetool: a fatal/binary $BASE/$LOCAL/$REMOTE must never open the viewer.
   true > "${gui_log}"
   "${mergetool_bin}" meld "${a}" "${b}" "${c}" "${m}" >/dev/null 2>&1 || true
   if [ -s "${gui_log}" ] && any_hostile "${a}" "${b}" "${c}"; then
      fails=$(( fails + 1 ))
      printf 'FAIL iter=%s: mergetool opened the viewer on a fatal/binary conflict side\n' "${i}" >&2
   fi
done

printf '\n==== wrapper fuzz FAILURES (hostile blob reached viewer): %s ====\n' "${fails}"
exit "${fails}"
