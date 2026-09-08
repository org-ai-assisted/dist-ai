# secure-terminal screenshot generators

All the screenshots on <https://secure-terminal.github.io> are produced here, by
committed generators. To update a shot, RE-RUN the generator; nothing is
hand-drawn. Each generator captures a PNG and then losslessly converts it to
`.webp` (via the shipped `image-optimize --webp`), because the site references
the shots as `.webp`; a regenerated shot therefore lands already optimized. One
entry point drives every lane:

    secure-terminal-shots [review|comparison|clipboard|...] [ARGS...]

They resolve a secure-terminal checkout from `SECURE_TERMINAL_REPO` (or a default
under `~/private-sources`).

## review (default) -> the site's `shots/` - the paste/copy review bar

`paste-warning.png`, `copy-warning.png` render the real
`secure_terminal.review.ReviewBar` headless (offscreen Qt `grab()`,
deterministic, no display). Generator: `paste-warning-shot.py <out.png>
[paste|copy]`; `secure-terminal-shots review` regenerates both at once.

## comparison -> the site's `comparison/shots/` - real terminals

`comparison-capture.sh` feeds hostile byte streams to a set of Debian terminal
emulators AND to secure-terminal, under a PRIVATE headless `labwc` compositor
(`WLR_BACKENDS=headless` + `WLR_RENDERER=pixman` -- software, no GPU, no host X
server), and screenshots each window with `grim`. The toolkit terminals and
secure-terminal run as NATIVE Wayland clients; the three X11-only emulators
(`xterm`/`urxvt`/`st`) run under labwc's own Xwayland. labwc draws the same real,
themed server-side title bar on EVERY window -- so an OSC-0 title hijack shows in
that bar as it would on a real desktop. It writes to its own `shots/`; copy those
to the site's `comparison/shots/`. Needs NO host X server; run it in a sandbox.

    # install the compositor + capture tools + emulators (this repo installs nothing itself):
    sudo apt install --no-install-recommends \
      xterm rxvt-unicode stterm konsole gnome-terminal xfce4-terminal mate-terminal \
      lxterminal qterminal alacritty kitty \
      labwc wlr-randr grim wtype imagemagick papirus-icon-theme

    # then, anywhere (no display needed -- labwc brings up its own headless output):
    SECURE_TERMINAL_REPO=/path/to/secure-terminal secure-terminal-shots comparison

### Running it in a sandbox

- `secure-terminal-shots-sandbox comparison` is the forget-proof driver: it fresh-syncs the
  secure-terminal / dist-ai / terminal-poc-corpus trees into temp-claude, preflights the capture
  stack, runs the lane there, and pulls the shots back into the site.
- Direct run, bypassing the wrapper (no display required):

      ST_REPO=/path/to/secure-terminal ALLOW_SKIP=1 ./comparison-capture.sh

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
- Reaping: each terminal + the secure-terminal GUI runs in its OWN session (setsid) and is
  reaped by the recorded PGID (`kill -- -PGID`), with a per-capture `SHOT_DEADLINE` (default
  90s) watchdog. The GUI runs as `python3 .../secure-terminal` (its shebang), so it is NEVER
  reaped by name (`pkill -x secure-terminal` misses it; `pkill -x python3` would hit unrelated
  GUIs). Orphans from a crashed run are marker-scoped (the run's unique mktemp dir, in every
  spawned argv -- the emulators via `--rcfile`, the GUI via the `SHOTS_RUN_MARKER` env); a
  startup pre-clean reaps the prior run, and `secure-terminal-shots --cleanup` reaps leftovers by
  hand. Discovery/sweep uses `safe-pgrep` / `safe-pkill` only -- their absence HARD-FAILS.

### Why comparison-capture.sh does what it does

- Locale: the emulators launch under `LC_ALL=C.UTF-8` (C collation, UTF-8 encoding). The harness
  runs under `LC_ALL=C` for deterministic payload BYTE generation, but a terminal must render
  those bytes as UTF-8 or the unicode attacks show as mojibake -- and, critically, the X11 trio
  (xterm/urxvt/st) SILENTLY EXIT under a non-UTF-8 locale (no window, no error).
- Injection: `wtype` drives the compositor's virtual keyboard, delivered to the focused window
  (native Wayland and Xwayland alike); labwc focuses the single window we just mapped. No keymap
  dance and no window-id needed. secure-terminal is driven instead by `ctl send-text --submit`
  (a real remote-control command) so the payload runs even without keyboard focus.
- cwd: each emulator is launched from the harness's private `${HOME}` by `cd`-ing in the LAUNCHER
  so a typed `cat crafted.payload` resolves. Keep `cd` OUT of the rcfile (`.strc`).
- Sizing: native Wayland has no external post-launch resize. Grid-honouring emulators (konsole
  `-p`, alacritty `-o`, kitty px, the Xwayland trio `-geometry`) size from their launch flags;
  the maximizing / geometry-ignoring ones (qterminal, and the GTK/VTE xfce4/mate/gnome) are pinned
  on MAP by a labwc `<windowRule><action name="ResizeTo">` keyed on their app-id (`set_window_rule`
  rewrites rc.xml + reconfigures labwc). secure-terminal is sized the same way (app-id
  `secure-terminal`).
- Favicon: the shots pass NO window-identity flag to secure-terminal. It sets its own Wayland
  app-id (`secure-terminal`, via `setDesktopFileName`) idiomatically, which labwc resolves through
  the Papirus theme -> hicolor -> the shipped `secure-terminal.svg`. Stamping a per-run temp path
  on `--class`/`--name` (the old reaping-marker trick) would become the app-id and force labwc's
  generic fallback, so the marker rides the `SHOTS_RUN_MARKER` env instead. `favicon_appid_test`
  guards this.
- Window height is CASE-AWARE. The short cases keep their prior heights so their committed on-page
  `<img>` dimensions do not move; only `tui-showcase` runs taller (its board paints ~26+ lines and
  would otherwise scroll its title bar off). `tighten_deadspace` trims each shot back to its own
  content.

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
ONCE in `lib-capture.sh`, sourced by `comparison-capture.sh`, so they cannot drift. The
attack bytes are NOT hand-written here: they are reproduced from the `terminal-poc-corpus`
(single source of truth, canary-forked and harness-verified) via its `tools/reproduce.py`,
so that checkout must ALSO be synced into the sandbox (resolved from `CORPUS_REPO` or a
default under `~/private-sources`; a missing corpus is a logged SKIP). Only the page-facing
`notify` demo and the `random` case are generated inline. The compositor/grab pipeline stays
in this generator; that is why it does NOT reuse private-ai-config's generic `headless-capture`.

### What you should see

Every traditional emulator interprets the escapes (corrupted screen, stuck colour
and charset, a silently rewritten title). secure-terminal reduces the stream to
inert printable ASCII: the title is never touched, the charset shift is literal
text, and the only colour is the bounded, contrast-guarded palette - the
attacker's invisible red-on-red is forced readable and can hide nothing.

Per-emulator caveat: kitty honours the OSC-0 title hijack, but its shell integration
RESETS the title to the cwd at the next prompt, so kitty's title bar can be clean in
the shot. Caption it honestly -- the other emulators leave the hijacked title stuck.

## Notes / gotchas

A few non-obvious things about `comparison-capture.sh` + its shared bringup worth knowing:

- **The compositor bringup is the shared `wl-headless-lib.bash`** (in
  `dist-ai-tests-common`): it starts `labwc WLR_BACKENDS=headless`, discovers the new Wayland
  socket and labwc's Xwayland display (by mtime, robust to stale sockets), installs a BLANK
  Xcursor (so a stray pointer never defeats the trim), points labwc at the Papirus icon theme, and
  raises the output to `SHOT_SCALE` via `wlr-randr`. `grim` grabs the whole output; a 1px black
  border + `-trim` crops exactly to the single window (labwc's default theme draws no shadow).
- **Every shot is captured at `SHOT_SCALE`x device resolution (default 2, i.e. HiDPI).** This is
  applied ONCE, at the source: the headless OUTPUT is set to scale `SHOT_SCALE`, so native Wayland
  clients AND labwc's SSD title bar render at 2x automatically, and labwc scales its Xwayland
  clients the same. No per-client scale env (`px()` is the identity). The character GRID (cols x
  rows) is unchanged -- only pixels-per-cell double. A 1x shot was blurry once a browser upscaled
  it on a HiDPI display (the raster, not webp compression: shots are lossless VP8L).
- **A blank/black grab is never shipped.** The emulator pass runs a sequential re-capture net that
  re-shoots any shot the parallel `--jobs` lanes left missing (a discarded blank leaves no file).
  Per shot, `capture_settled` retries a blank grab before returning, and `st_wait_render_settled`
  waits for a REAL settle (two consecutive matching grabs, wall-clock bounded under `SHOT_DEADLINE`)
  so a slow row-by-row board is not grabbed half-drawn. A spec that never renders is discarded with
  a `warn`, never emitted as black, and any prior good shot is left intact.

## Related

- `terminal-resilience-tests` (also in dist-ai) is the automated invariant version
  of the comparison: it asserts a traditional emulator's title IS hijacked and
  secure-terminal's output carries no escape byte and no title marker.
- The adversarial byte-stream corpus secure-terminal is tested against lives in
  the `terminal-poc-corpus` repo.
