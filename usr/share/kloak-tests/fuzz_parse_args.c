/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's remaining untrusted command-line value parsers:
 * parse_uint_arg (the --delay / --start-delay / --color numeric arguments, at
 * both its INT32_MAX and UINT32_MAX caps) and lookup_keycode (the key names in
 * --escape-keys).
 * parse_esc_key_str has its own harness; together these cover the CLI
 * string->value surface.
 *
 * Unlike parse_esc_key_str these are return-based (no exit() on bad input) and
 * allocate nothing, so no exit interception or global reset is needed; a crash
 * under ASAN/UBSAN is the only finding.
 *
 * Maintained HERE in dist-ai (not vendored in the kloak submodule); the
 * kloak-tests-fuzz runner stages it into kloak's build tree's fuzz/ dir, hence
 * the "../src/kloak.c" include relative to that staged location.
 */

/* kloak.c uses _GNU_SOURCE symbols (memfd_create, environ); define it before any
 * system header, since this file includes them before kloak.c. */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = NULL;
  uint32_t v = 0;

  buf = malloc(size + 1U);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  (void)parse_uint_arg(buf, 10, INT32_MAX, &v);
  (void)parse_uint_arg(buf, 16, INT32_MAX, &v);
  (void)parse_uint_arg(buf, 10, UINT32_MAX, &v);
  (void)parse_uint_arg(buf, 16, UINT32_MAX, &v);
  (void)lookup_keycode(buf);

  free(buf);
  return 0;
}
