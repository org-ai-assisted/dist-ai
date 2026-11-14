/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

libFuzzer harness for kloak's SCREEN-GEOMETRY processing in the sandboxed
Wayland adapter (src/kloakwl.c): recalc_global_space's O(n^2) screen-connectivity
scan over a compositor-supplied set of output geometries, plus the global-space
coordinate transform (abs_coord_to_screen_local_coord) on an accepted layout.

recalc_global_space is out of CBMC scope (its connectivity scan over symbolic
geometry does not converge) and was only unit-tested with a few hand-built
layouts; the input_sequence harness pins geometry to ONE fixed two-monitor setup.
This harness varies the layout itself -- count, origins (incl. negative, for a
monitor left of / above the primary), extents, overlaps, gaps -- which is the
real untrusted "screen geometry" surface the audit flagged.

Geometry values are kept in a realistic bounded envelope (|coord| <= 100000,
extent <= 100000, up to MAX_SCREEN_COUNT outputs), so the global span stays well
inside INT32 and the fuzzer explores the CONNECTIVITY/overlap LOGIC and its
reject path, not kloak's by-design defensive asserts on adversarial INT32
extremes (the hostile-compositor -ftrapv WONTFIX class). Built by ci/cfuzz-build.sh
with ASan + UBSan (minus signed-overflow, which -fwrapv defines), so it surfaces
real memory-safety bugs in the scan.
*/
#define KLOAK_FUZZING
#include "../src/kloakwl.c"

#include <stdint.h>
#include <string.h>

#define GEOM_COORD_LIMIT 100000

/* Backing storage for the fuzzed geometries; state.output_geometries holds
 * pointers into this for the duration of one recalc_global_space call. */
static struct output_geometry fuzz_geoms[MAX_SCREEN_COUNT];

/* Map an arbitrary word into [-GEOM_COORD_LIMIT, GEOM_COORD_LIMIT] via unsigned
 * modulo (no signed overflow concern). */
static int32_t bounded_coord(uint32_t v) {
  return (int32_t)(v % (uint32_t)(GEOM_COORD_LIMIT * 2 + 1)) - GEOM_COORD_LIMIT;
}

/* Map an arbitrary word into [0, GEOM_COORD_LIMIT] (extents are non-negative). */
static int32_t bounded_extent(uint32_t v) {
  return (int32_t)(v % (uint32_t)(GEOM_COORD_LIMIT + 1));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t off = 0;
  ssize_t count = 0;
  ssize_t i = 0;
  uint32_t raw[4] = { 0, 0, 0, 0 };
  int32_t qx = 0;
  int32_t qy = 0;

  if (size < 1) {
    return 0;
  }
  /* First byte: how many outputs (1 .. MAX_SCREEN_COUNT). */
  count = (ssize_t)(data[off++] % (unsigned)(MAX_SCREEN_COUNT)) + 1;

  for (i = 0; i < MAX_SCREEN_COUNT; i++) {
    state.output_geometries[i] = NULL;
  }
  for (i = 0; i < count; i++) {
    if (off + sizeof(raw) > size) {
      break;
    }
    memcpy(raw, data + off, sizeof(raw));
    off += sizeof(raw);
    fuzz_geoms[i].x = bounded_coord(raw[0]);
    fuzz_geoms[i].y = bounded_coord(raw[1]);
    fuzz_geoms[i].width = bounded_extent(raw[2]);
    fuzz_geoms[i].height = bounded_extent(raw[3]);
    state.output_geometries[i] = &fuzz_geoms[i];
  }

  /* The scan under test. A disconnected/gapped layout is rejected (returns
   * false) -- a normal outcome, not a crash; both paths exercise the scan. */
  if (recalc_global_space()) {
    /* On an accepted layout, drive the global-space transform with a fuzzed
     * query point so the pointer_space offsets it computed are used. */
    if (off + sizeof(int32_t) * 2 <= size) {
      memcpy(&qx, data + off, sizeof(qx));
      off += sizeof(qx);
      memcpy(&qy, data + off, sizeof(qy));
      off += sizeof(qy);
      (void)abs_coord_to_screen_local_coord(
        bounded_coord((uint32_t)(qx)), bounded_coord((uint32_t)(qy)));
    }
  }

  for (i = 0; i < MAX_SCREEN_COUNT; i++) {
    state.output_geometries[i] = NULL;
  }
  return 0;
}
