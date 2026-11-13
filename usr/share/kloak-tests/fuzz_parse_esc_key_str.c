/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's parse_esc_key_str() -- the escape-key spec
 * parser (comma-separated keys, '|'-separated chords) fed from --escape-keys on
 * the command line. Unlike the parse_uint* parsers, it is NOT return-based: it
 * fatal-errors (errx) on malformed input (empty token, unrecognized key name),
 * and the
 * escape-key globals it builds (esc_key_list / esc_key_sublist_len /
 * active_esc_key_list) live for the program's lifetime and are never freed.
 *
 * This harness is maintained HERE in dist-ai (not vendored in the kloak
 * submodule); the kloak-tests-fuzz runner stages it into kloak's build tree's
 * fuzz/ dir so kloak's own ci/cfuzz-build.sh compiles it (hence the
 * "../src/kloak.c" include, relative to that staged fuzz/ location).
 *
 * Two consequences this harness handles so the REAL parser can be fuzzed
 * in-process without a kloak source change:
 *   1. The fatal paths (exit(), err(), errx()) are INTERCEPTED (redefined to
 *      longjmp before including kloak.c): a fatal rejection unwinds back here as
 *      "input rejected", so only genuine UB (ASAN/UBSAN) is a finding, not every
 *      malformed string.
 *   2. The globals are reset (freed + zeroed) each iteration, and LeakSanitizer
 *      is disabled for this target -- the parser intentionally leaves those
 *      globals allocated (production exits), so a "leak" is not a defect here.
 *
 * Pulling kloak.c in via #include keeps the target's file-scope `static` intact;
 * the Wayland/libinput code is dead (never called) during fuzzing.
 */

/* kloak.c uses _GNU_SOURCE symbols (memfd_create, environ); define it before any
 * system header, since this file includes them before kloak.c. */
#define _GNU_SOURCE

#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

/* Intercept kloak's fatal exits: parse_esc_key_str's rejection of bad input is
 * handled, not a crash. It rejects via <err.h> (errx), so intercept err()/
 * errx() as well as exit() -- an exit()-only macro would let errx's libc exit()
 * escape and libFuzzer would read it as a crash. Defined AFTER the real
 * declarations are parsed (<stdlib.h>, <err.h>) and BEFORE kloak.c, whose
 * guarded re-includes are a no-op, so only kloak.c's CALLS expand. warn()/
 * warnx() are non-fatal and left alone. */
static jmp_buf g_reject;
#define exit(code) longjmp(g_reject, 1)
#define err(code, ...) longjmp(g_reject, 1)
#define errx(code, ...) longjmp(g_reject, 1)

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

/* The escape-key globals are never freed by kloak (program-lifetime state), so
 * LeakSanitizer would flag them every run; this target checks memory safety and
 * UB, not leaks. */
const char *__asan_default_options(void) {
  return "detect_leaks=0";
}

static void reset_esc_globals(void) {
  if (esc_key_list != NULL) {
    for (size_t i = 0; i < esc_key_list_len; i++) {
      free(esc_key_list[i]);
    }
    free(esc_key_list);
  }
  free(esc_key_sublist_len);
  free(active_esc_key_list);
  esc_key_list = NULL;
  esc_key_sublist_len = NULL;
  active_esc_key_list = NULL;
  esc_key_list_len = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = malloc(size + 1U);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  reset_esc_globals();
  if (setjmp(g_reject) == 0) {
    parse_esc_key_str(buf);
  }
  reset_esc_globals();

  free(buf);
  return 0;
}
