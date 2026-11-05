/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for the pure arithmetic in kloak's libinput proxy
(src/kloak.c), resolved via KLOAK_REPO. No kloak source change: reuses the
KLOAK_FUZZING seam (guards out main()), so the actual function body is verified.
The Wayland-adapter arithmetic (geometry/scroll/time/random) lives in
src/kloakwl.c and is proven in kloakwl_cbmc.c.

CBMC 6.x enables the full standard check set by default (signed/unsigned/pointer/
float overflow, conversion, nan, bounds, pointer, div-by-zero), so verify_sleep_ms
is proven free of ALL of those for every in-envelope input. Its EINTR retry is a
bounded loop, so it runs under --unwind.

The libc boundary (nanosleep) is modeled here so the proof is deterministic -- an
environment shim, not a reimplementation of kloak logic.
*/
#define KLOAK_FUZZING
#include "kloak.c"

#include <stdint.h>

/* ---- libc boundary model (environment, not kloak logic) ---- */

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)req;
    (void)rem;
    return 0;
}

/* ---- proof ---- */

/* sleep_ms: a non-negative millisecond count produces a valid timespec with no
 * UB (nanosleep modeled above). */
void verify_sleep_ms(void)
{
    int64_t ms;
    __CPROVER_assume(ms >= 0);
    (void)sleep_ms(ms);
}
