# secure-terminal screenshot generators

All the screenshots on <https://secure-terminal.github.io> are produced here, by
committed generators. To update a shot, RE-RUN the generator; nothing is
hand-drawn. Each generator captures a PNG and then losslessly converts it to
`.webp` (via the shipped `image-optimize --webp`), because the site references
the shots as `.webp`; a regenerated shot therefore lands already optimized. One
entry point drives both:

    secure-terminal-shots [review|comparison|comparison-wayland] [ARGS...]

Both resolve a secure-terminal checkout from `SECURE_TERMINAL_REPO` (or a default
under `~/private-sources`).

## review (default) -> the site's `shots/` - the paste/copy review bar

`paste-warning.png`, `copy-warning.png` render the real
`secure_terminal.review.ReviewBar` headless (offscreen Qt `grab()`,
deterministic, no display). Generator: `paste-warning-shot.py <out.png>
[paste|copy]`; `secure-terminal-shots review` regenerates both at once.

## comparison -> the site's `comparison/shots/` - real terminals

`comparison-capture.sh` feeds two hostile byte streams to a set of Debian
terminal emulators AND to secure-terminal, under a nested `labwc` compositor (the
wlroots compositor LXQt ships) on the host X server, with the Clearlooks Openbox
theme - so an OSC-0 title hijack shows in the same real, themed title bar it would
on an LXQt desktop. It writes to its own `shots/`; copy those to the site's
`comparison/shots/`. **Needs an X server + labwc**, so run it in a sandbox.

    # install the emulators + compositor (this repo installs nothing itself):
    sudo apt install --no-install-recommends \
      xterm rxvt-unicode stterm konsole gnome-terminal xfce4-terminal mate-terminal \
      lxterminal qterminal alacritty kitty \
      labwc openbox xdotool wmctrl x11-utils x11-xserver-utils imagemagick

    # then, on a machine with an X server on $DISPLAY:
    SECURE_TERMINAL_REPO=/path/to/secure-terminal secure-terminal-shots comparison

### Running it in a sandbox

- The host dev VM has no compositor/WM tooling: add `labwc openbox wmctrl` to the
  apt line above.
- `labwc` nests on the sandbox's X server (`WLR_BACKENDS=x11`, set by the harness);
  it only needs a real `$DISPLAY` (defaults to `:0`).
- Direct run, bypassing the wrapper:

      ST_REPO=/path/to/secure-terminal DISPLAY=:0 ALLOW_SKIP=1 ./comparison-capture.sh

  `ALLOW_SKIP=1` authorizes a LOGGED skip of a missing emulator (or of
  secure-terminal); without it a missing one is a hard error, because an incomplete
  grid misrepresents the comparison.
- `urxvt`: on a hardened Kicksecure/Whonix system the permission-hardener strips its
  exec bit -- no window, `env: '_urxvt_': Permission denied`. Restore it first:
  `sudo chmod a+x /usr/bin/urxvt`.
- `python3-confusable-homoglyphs` must be READABLE by the capturing user (apt-install
  it, or `sudo chmod -R a+rX` a hand-copied package tree). Its loader swallows every
  error, so unreadable `confusables.json` degrades SILENTLY: the Cyrillic byte drops
  out of the `confusable` class (rose) into plain `nonascii` (purple) and the
  homoglyph shots are subtly wrong with no warning.
- Fetching the PNGs back out: `qube-ctl pull REMOTE LOCAL_DIR` treats the 2nd arg as
  a DIRECTORY (files land in `LOCAL_DIR/<basename-of-REMOTE>/`) and MERGES into an
  existing target. Pull into a FRESH empty dir, or stale shots from an earlier run
  contaminate the set.
- Reaping: each terminal + the secure-terminal GUI runs in its OWN session (setsid) and is
  reaped by the recorded PGID (`kill -- -PGID`), with a per-capture `SHOT_DEADLINE` (default
  90s) watchdog. The GUI runs as `python3 .../secure-terminal`, so it is NEVER reaped by name
  (`pkill -x secure-terminal` misses it; `pkill -x python3` would hit unrelated GUIs). Orphans
  from a crashed run are marker-scoped (the run's unique mktemp dir, in every spawned argv);
  a startup pre-clean reaps the prior run, and `secure-terminal-shots --cleanup` reaps leftovers
  by hand. Discovery/sweep uses `safe-pgrep` / `safe-pkill` only -- their absence HARD-FAILS.

### Why comparison-capture.sh does what it does

X11 path only. `wayland-capture.sh` prints the prompt itself and runs the command via
`sh -c`, so the typing and cwd items below do not apply to it.

- Keymap: `xdotool type` mangles symbols (`/` arrives as `&`) unless `setxkbmap us`
  runs on the Xwayland display. A newly connecting Xwayland client resets the keymap,
  so `inject()` re-applies it before EVERY injection, not once at startup.
- cwd: each emulator is launched from the harness's private `${HOME}` by `cd`-ing in
  the LAUNCHER, so a typed `cat crafted.payload` resolves. Keep `cd` OUT of the rcfile
  (`.strc`) -- the shell inside secure-terminal sees a different `$HOME`, would walk
  away from the payload logs, and `cat crafted.payload` would fail under a caption
  claiming a hijack that never happened.
- qterminal: ignores `-geometry` and opens MAXIMIZED, ignoring a plain resize.
  `shoot()` special-cases it -- `wmctrl -b remove,maximized_vert,maximized_horz`, then
  `xdotool windowsize 720 <h>` (`<h>` is the case's resize height). Window SELECTION is
  not special-cased: `find_window()` picks the largest new non-baseline window for every
  emulator.
- Under labwc the random stream does not shrink or kill windows, so all 10 emulators
  yield a random shot too. A generic post-injection rescue still resizes any window
  left narrower than 300px.
- Window height is CASE-AWARE. The short cases run at 84x24 (kitty/qterminal at their
  prior pixel heights) so their shots -- and the committed on-page `<img>` dimensions --
  do not move. Only `tui-showcase` runs taller (84x32; kitty/qterminal/ST resized up),
  because its board paints ~26 lines on the alternate screen and would otherwise scroll
  its title bar off the top. `launch()`/`shoot()` take the case; the ST loop picks
  `st_win_h` per case. `tighten_deadspace` trims each shot back to its own content.

### The payloads (inputs to the comparison)

- **Case A - random.** `cat random.payload`: a fixed pseudo-random garble field,
  seeded and deterministic (regeneration is byte-identical), ESC bytes filtered
  out so it carries no crafted escapes.
- **Case B - a crafted hostile log.** `crafted.payload` carries, mid-stream, the
  escapes real hostile output can carry: `OSC 0` (silently rewrites the window
  title, never reset), `SGR 31;41` (a stuck red-on-red), and `ESC ( 0` (a DEC
  line-drawing charset shift, never reset). Just `cat`-ing it IS the attack; read it
  safely with `cat -v` / `hexdump -C`. Its bytes come from the terminal-poc-corpus
  `crafted-hostile-log` PoC (decoded by the corpus `tools/reproduce.py`).
- **Case C - homoglyph.** `homoglyph.payload`: a domain hiding a Cyrillic look-alike
  (U+0430 for Latin a), from the corpus `homoglyph-domain-install-2021` PoC.
- **Case D - tui-showcase.** `tui-showcase.payload`: ONE safe, display-only board that
  exercises every text-attack class at once (homoglyph, bidi, zero-width, BOM,
  combining, fullwidth, control-byte CR+erase, hidden-by-colour SGR, DEC charset, OSC 8
  hyperlink, OSC 0 title, `?1049h` alt-screen, plus honest foreign text as the non-attack
  contrast). `cat`-ing it paints a full-screen "what you see vs what is there" table;
  secure-terminal is shot in BOTH box and detail. From the corpus `tui-showcase` PoC.
- **alt-screen** (`#altscreen` on the page). `altscreen.payload`: flips the terminal
  into its alternate screen buffer (the full-screen mode pagers and editors use) and
  never switches back, a whole-screen takeover entered silently on stray output, from the
  corpus `alt-screen-hijack` PoC.
- **notify** (`#notify` on the page). `notify.payload`: an `OSC 9` desktop-notification
  from a build-log line, with deliberately safe page-facing wording -- generated inline,
  not a corpus detection payload.

These cases (the payload command + which corpus PoC supplies its bytes) are defined
ONCE in `lib-capture.sh`, sourced by both comparison generators - the X11
`comparison-capture.sh` and the native-Wayland `wayland-capture.sh` - so the cases
cannot drift between them. The attack bytes are NOT hand-written here: they are
reproduced from the `terminal-poc-corpus` (single source of truth, canary-forked and
harness-verified) via its `tools/reproduce.py`, so that checkout must ALSO be synced
into the sandbox (resolved from `CORPUS_REPO` or a default under `~/private-sources`;
a missing corpus is a logged SKIP). Only the page-facing `notify` demo and the
`random` case are generated inline. The compositor/grab pipeline stays per-generator;
that is why they do NOT reuse private-ai-config's generic `headless-capture`.

### What you should see

Every traditional emulator interprets the escapes (corrupted screen, stuck colour
and charset, a silently rewritten title). secure-terminal reduces the stream to
inert printable ASCII: the title is never touched, the charset shift is literal
text, and the only colour is the bounded, contrast-guarded palette - the
attacker's invisible red-on-red is forced readable and can hide nothing.

Per-emulator caveat: kitty honours the OSC-0 title hijack, but its shell integration
RESETS the title to the cwd at the next prompt, so kitty's title bar can be clean in
the shot. Caption it honestly -- the other emulators leave the hijacked title stuck.

## Related

- `terminal-resilience-tests` (also in dist-ai) is the automated invariant version
  of the comparison: it asserts a traditional emulator's title IS hijacked and
  secure-terminal's output carries no escape byte and no title marker.
- The adversarial byte-stream corpus secure-terminal is tested against lives in
  the `terminal-poc-corpus` repo.
