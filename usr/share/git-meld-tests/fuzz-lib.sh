#!/bin/bash
## Fuzzer for git-meld's core invariant: EVERY path git reports as changed must
## appear in what a reviewer running 'git meld' sees. If git sees a change that
## git-meld renders as nothing, that is a hidden change (fail).
##
## Deterministic given a seed (bash 'RANDOM=<seed>'). Safe payloads only; meld
## stubbed. Usage: fuzz-lib.sh /path/to/git-meld <iterations> <seed>
## style-ok: no-safe-rm (rm only touches throwaway mktemp workspaces)
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

GIT_MELD="$(readlink -f -- "${1:?git-meld path}")"
iters="${2:-200}"
seed="${3:-1}"

work="$(mktemp -d)"; export HOME="${work}/home"; mkdir -p "${HOME}"
git config --global user.email t@example.com; git config --global user.name test
git config --global init.defaultBranch master
mkdir -p "${work}/bin"; meld_log="${work}/display.log"
for gui in meld kdiff3; do
   { printf "%s\n" "#!/bin/bash"; printf '%s\n' "printf \"DISPLAY %s"$'\\'"n\" \"\$*\">>\"${meld_log}\""; } >"${work}/bin/${gui}"
   chmod +x "${work}/bin/${gui}"
done
export PATH="${work}/bin:${PATH}"

RANDOM="${seed}"
fails=0

## A random safe blob: sometimes plain text, sometimes with control/NUL/unicode
## bytes, sometimes long lines, sometimes gitlink-mimicking content.
rand_blob () {
   local kind=$((RANDOM % 6))
   case "${kind}" in
      0)
         printf '%s\n' "line ${RANDOM}" "code ${RANDOM}"
         ;;
      1)
         printf '%s\0' 'a'                                               ## auto-binary
         printf '%s\n' "b NUL embedded ${RANDOM}"
         ;;
      2)
         printf '%s\n' "x # "$'\xe2\x80\xae\xe2\x81\xa6'"hidden"$'\xe2\x81\xa9'" ${RANDOM}" ## bidi
         ;;
      3)
         printf -v fake_sha '%040d' "${RANDOM}"                          ## gitlink mimic
         printf '%s\n' "Subproject commit ${fake_sha}"
         ;;
      4)
         ## long
         head -c $(( (RANDOM % 4000) + 1 )) /dev/zero | tr '\0' 'A'
         printf '%s\n' ''
         ;;
      5)
         printf '%s\n' $'\xef\xbb\xbf'"bom ${RANDOM}"                       ## BOM/zero-width
         ;;
   esac
}

printf '%s\n' "== git-meld fuzz: ${iters} iters, seed ${seed}, ${GIT_MELD} =="
i=0
while [ "${i}" -lt "${iters}" ]; do
   i=$((i + 1))
   r="${work}/r"; rm -rf "${r}"; git init -q "${r}"; cd "${r}"
   ## baseline: a few files
   for n in f1 f2 f3; do rand_blob > "${n}"; done
   git add -A >/dev/null 2>&1; git commit -qm base >/dev/null 2>&1 || { continue; }

   ## random mutation
   case $((RANDOM % 7)) in
      0)
         ## content change
         rand_blob > f1
         ;;
      1)
         ## mode-only
         chmod +x f2
         ;;
      2)
         ## file->symlink
         rm f3
         ln -s "/etc/passwd" f3
         ;;
      3)
         ## add file
         rand_blob > "f_new_${RANDOM}"
         ;;
      4)
         ## delete file
         rm f1
         ;;
      5)
         ## rename
         git mv f2 "f2_renamed" 2>/dev/null || rand_blob > f2
         ;;
      6)
         ## attrs+change
         printf '%s\n' "x.data binary" > .gitattributes
         rand_blob > f2
         ;;
   esac
   git add -A >/dev/null 2>&1
   git commit -qm mut >/dev/null 2>&1 || continue

   ## paths git considers changed (authoritative, external-diff-independent)
   mapfile -t changed < <(git diff --no-ext-diff --name-only HEAD~1 HEAD)
   [ "${#changed[@]}" -eq 0 ] && continue

   true > "${meld_log}"
   seen="$( "${GIT_MELD}" HEAD~1 HEAD 2>&1 || true )$(cat "${meld_log}")"

   for path in "${changed[@]}"; do
      ## the changed path (basename, to dodge temp-dir noise) must appear in
      ## what the reviewer sees -- otherwise git-meld hid a real change.
      base="${path##*/}"
      if ! grep --fixed-strings --quiet -- "${base}" <<< "${seen}"; then
         fails=$((fails + 1))
         printf '%s\n' "FAIL iter=${i}: changed path ${path} NOT surfaced by git-meld" >&2
         printf '%s\n' "  git saw: ${changed[*]}" >&2
         printf '%s\n' "  reviewer saw: $(printf '%s' "${seen}"|tr '\n' '|'|cut -c1-160)" >&2
      fi
   done
done

printf '%s\n' "" "==== fuzz FAILURES (hidden changes): ${fails} ===="
rm -rf "${work}"; exit "${fails}"
