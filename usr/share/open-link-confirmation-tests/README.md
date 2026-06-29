# open-link-confirmation tests

Security and unit tests for the Kicksecure
[open-link-confirmation](https://github.com/Kicksecure/open-link-confirmation)
link/file confirmation dialog.

## What it tests

`open-link-confirmation` is the `$BROWSER` / `x-www-browser` handler. It
receives a URL or file path from a potentially untrusted source (a clicked
link, another application, a downloaded file) and shows a confirmation dialog
before opening it. The argument is the untrusted input; the threat model is
"what can a crafted argument make that dialog show or do".

The argument is displayed by piping it through helper-scripts'
`sanitize-string` and embedding the result in an HTML message that
msgcollector's `generic_gui_message` renders in a PyQt5 `QTextBrowser`
(`setOpenExternalLinks(True)`). The suite covers that whole pipeline:

- **[A] Sanitization contract** - drives the real `sanitize-string -- 128
  <arg>` over a hostile battery (Unicode, RTL override, zero-width, ANSI/SGR,
  OSC-8 hyperlinks, C0/C1/DEL control bytes, oversized inputs, markup) and
  asserts the output is display-safe: ASCII only, length `<= 128`, no
  ESC/control bytes other than newline and tab.
- **[B] Qt rich-text differential** - embeds the sanitized output in the
  script's exact HTML wrapper and parses it with the real Qt `QTextDocument`
  (the engine `QTextBrowser.setText` uses), asserting the argument introduces
  no anchor (`<a href>`) or image (`<img>`). This is where a parser
  differential bites (see the finding below).
- **[C] Static audit** - reads the script and asserts every displayed message
  interpolates only the sanitized representation of the argument, never the
  raw argument.
- **[D] Env-over-config precedence** (`env_override_test.sh`) - extracts the
  real `source_config()`, sandboxes its config directories, and asserts the
  on-disk `/etc/open_link_confirm.d/*.conf` files are the baseline while a
  value provided via the environment wins over them.

No root, no network, no real browser. Qt runs offscreen
(`QT_QPA_PLATFORM=offscreen`); group B is skipped if PyQt5 is absent. Group D
skips on a copy of the script that predates the env-override feature.

## Running

    open-link-confirmation-tests

From a checkout, or to test specific components:

    OPEN_LINK_CONFIRMATION_BIN=/path/to/open-link-confirmation \
    SANITIZE_STRING_BIN=/path/to/sanitize-string \
    ./usr/bin/open-link-confirmation-tests

## Known finding: markup injection via parser differential

Group B documents a real, currently-unfixed issue as strict-xfail cases
(`KNOWN_VULN` in `open_link_confirmation_test.py`):

`sanitize-string` strips markup with Python's `html.parser`, which treats a
`<` followed by whitespace then a tag name (`< a href=...>`, `<\timg src=...>`,
`<\na ...>`) as inert literal text and passes it through verbatim - including
the whitespace, which `sanitize-string` also permits. Qt's rich-text parser is
more lenient: it skips the whitespace and reconstructs the tag. The result is
an attacker-controlled clickable `<a href>` (opened externally because of
`setOpenExternalLinks(True)`), or an `<img>` fragment, injected into a dialog
that is supposed to display only the URL being confirmed.

Confirmed: the anchor is materialized and clickable. Not confirmed: an
automatic resource fetch for the `<img>` form (a headless render did not invoke
`loadResource`); the image / IP-leak escalation needs an on-screen test.

If a fix lands (e.g. `sanitize-string` neutering any residual `<`, or the
consumer HTML-escaping the sanitized value before embedding it), these xfail
cases start passing and the suite will FAIL asking you to promote them to hard
controls - that is the intended signal that the bypass is closed.
