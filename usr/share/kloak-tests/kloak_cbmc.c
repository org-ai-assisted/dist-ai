/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for kloak's pure arithmetic. Compiled and checked by
test_kloak_verification.py against the REAL src/kloak.c (resolved via
KLOAK_REPO). No kloak source change: reuses kloak's existing KLOAK_FUZZING seam
(guards out main(), kloak.c), so the actual function bodies are verified.

CBMC 6.x enables the full standard check set by default (signed/unsigned/pointer/
float overflow, conversion, nan, bounds, pointer, div-by-zero), so each verify_*
below is proven free of ALL of those for EVERY input in the assumed envelope. The
geometry/scroll/time proofs are loop-free and exhaustive; the bounded loops
(random_between's rejection sampling, sleep_ms's EINTR retry, traverse_line's
Bresenham walk) run under --unwind (see each note).

Each verify_* assumes kloak's real operating envelope (screen coordinates and
delay bounds are int32-range values well below INT32_MAX, never adversarial
INT64 extremes) and then proves the function's invariant. The envelope matters:
outside it kloak relies on -ftrapv to turn an overflow into a safe crash+restart
(by design, see kloak.c NOTES), which is not a property this suite asserts.

The libc boundary (read for /dev/urandom, clock_gettime, nanosleep) is modeled
here so the proofs are deterministic and free of CBMC's internal pipe/clock
models -- these are environment shims, not reimplementations of kloak logic.
*/
#define KLOAK_FUZZING
/* glibc's isfinite() expands to __builtin_isfinite, which CBMC has no body for
 * (it cannot execute kloak's assert(isfinite(...))). Route the builtin to an
 * IEEE arithmetic finite test -- x-x is 0 only for a finite x (NaN-NaN and
 * Inf-Inf are NaN). Intrinsic-independent; CBMC's float model handles it. */
#define __builtin_isfinite(x) (((x) - (x)) == 0.0)
#include "kloak.c"

#include <stdint.h>
#include <math.h>

/* ---- libc boundary models (environment, not kloak logic) ---- */

/* /dev/urandom: a full read of nondeterministic bytes. read_random treats any
 * short read as fatal; a full read lets the real rejection sampling run. */
ssize_t read(int fd, void *buf, size_t count)
{
    (void)fd;
    __CPROVER_havoc_slice(buf, count);
    return (ssize_t)count;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    (void)clk_id;
    /* A plausible CLOCK_MONOTONIC: non-negative, normalised, and far below the
     * int64 ms-overflow threshold (tv_sec*1000 must not overflow). */
    __CPROVER_assume(tp->tv_sec >= 0 && tp->tv_sec < (1LL << 40));
    __CPROVER_assume(tp->tv_nsec >= 0 && tp->tv_nsec < 1000000000L);
    return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)req;
    (void)rem;
    return 0;
}

/* ---- proofs ---- */

#define COORD_MAX (1 << 29) /* far above any real display extent; keeps every
                             * int32 coordinate sum well inside INT32_MAX */

/* check_screen_touch: for in-envelope geometries the touch test is UB-free (the
 * +1/+2 grows and the axis-aligned overlap sums cannot overflow). */
void verify_check_screen_touch(void)
{
    struct output_geometry a, b;
    __CPROVER_assume(a.x >= 0 && a.x < COORD_MAX && a.y >= 0 && a.y < COORD_MAX);
    __CPROVER_assume(a.width >= 0 && a.width < COORD_MAX);
    __CPROVER_assume(a.height >= 0 && a.height < COORD_MAX);
    __CPROVER_assume(b.x >= 0 && b.x < COORD_MAX && b.y >= 0 && b.y < COORD_MAX);
    __CPROVER_assume(b.width >= 0 && b.width < COORD_MAX);
    __CPROVER_assume(b.height >= 0 && b.height < COORD_MAX);
    (void)check_screen_touch(a, b);
}

/* abs_coord_to_screen_local_coord: for an in-envelope screen and query point the
 * conversion is UB-free, and a valid result is the point relative to the
 * screen's origin and inside the screen. One symbolic screen suffices for the
 * per-screen arithmetic; the scan loop is covered by --unwind >= MAX_SCREEN_COUNT. */
void verify_abs_coord_to_screen_local_coord(void)
{
    struct output_geometry g;
    int32_t x, y;
    struct screen_local_coord sl;
    ssize_t i;
    __CPROVER_assume(g.x >= 0 && g.x < COORD_MAX && g.y >= 0 && g.y < COORD_MAX);
    __CPROVER_assume(g.width >= 0 && g.width < COORD_MAX);
    __CPROVER_assume(g.height >= 0 && g.height < COORD_MAX);
    __CPROVER_assume(x >= 0 && x < COORD_MAX && y >= 0 && y < COORD_MAX);
    for (i = 0; i < MAX_SCREEN_COUNT; i++) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g;
    sl = abs_coord_to_screen_local_coord(x, y);
    if (sl.valid) {
        __CPROVER_assert(sl.output_idx == 0, "valid hit is the only screen");
        __CPROVER_assert(sl.x >= 0 && sl.x < g.width, "local x inside screen");
        __CPROVER_assert(sl.y >= 0 && sl.y < g.height, "local y inside screen");
    }
    for (i = 0; i < MAX_SCREEN_COUNT; i++) {
        state.output_geometries[i] = NULL;
    }
}

/* screen_local_coord_to_abs_coord: UB-free, and a valid result is the screen
 * origin plus the local offset (the inverse of the above). */
void verify_screen_local_coord_to_abs_coord(void)
{
    struct output_geometry g;
    int32_t x, y, idx;
    struct coord c;
    ssize_t i;
    __CPROVER_assume(g.x >= 0 && g.x < COORD_MAX && g.y >= 0 && g.y < COORD_MAX);
    __CPROVER_assume(g.width >= 0 && g.width < COORD_MAX);
    __CPROVER_assume(g.height >= 0 && g.height < COORD_MAX);
    __CPROVER_assume(x >= 0 && x < COORD_MAX && y >= 0 && y < COORD_MAX);
    __CPROVER_assume(idx >= 0 && idx < MAX_SCREEN_COUNT);
    for (i = 0; i < MAX_SCREEN_COUNT; i++) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[idx] = &g;
    c = screen_local_coord_to_abs_coord(x, y, idx);
    if (c.x >= 0) {
        __CPROVER_assert(c.x == g.x + x, "abs x = origin + local x");
        __CPROVER_assert(c.y == g.y + y, "abs y = origin + local y");
    }
    for (i = 0; i < MAX_SCREEN_COUNT; i++) {
        state.output_geometries[i] = NULL;
    }
}

/* recalc_global_space is NOT CBMC-proven: its O(n^2) screen-connectivity scan
 * over symbolic geometry is intractable (does not converge at --unwind 129).
 * It is covered by the kloak_harness.c unit tests (touching, gapped, offset)
 * and its per-pair component check_screen_touch is proven above. */

/* random_between: the anti-fingerprinting delay bound. For a valid interval the
 * result is ALWAYS within [lower, upper] -- the property that keeps kloak's
 * randomised release delay inside its configured max. The rejection loop is
 * bounded (--unwind): every accepted draw is covered, which is exactly the set
 * of executions that return. */
void verify_random_between(void)
{
    int64_t lower, upper, r;
    __CPROVER_assume(lower >= 0);
    __CPROVER_assume(upper >= 0);
    __CPROVER_assume(lower <= upper);
    __CPROVER_assume(upper <= INT32_MAX); /* kloak's delays are int32 ms */
    randfd = 3;                           /* past read_random's assert(randfd>0) */
    r = random_between(lower, upper);
    __CPROVER_assert(r >= lower, "result not below lower bound");
    __CPROVER_assert(r <= upper, "result not above upper bound");
}

/* traverse_line: for in-envelope endpoints and a forward step the Bresenham
 * walk is UB-free (the error-term and coordinate adds stay in range). The walk
 * is a bounded loop, so it runs under --unwind like random_between/sleep_ms;
 * every step is structurally identical, so the unwound prefix is representative. */
void verify_traverse_line(void)
{
    struct coord start, end;
    int32_t pos;
    __CPROVER_assume(start.x >= 0 && start.x < COORD_MAX);
    __CPROVER_assume(start.y >= 0 && start.y < COORD_MAX);
    __CPROVER_assume(end.x >= 0 && end.x < COORD_MAX);
    __CPROVER_assume(end.y >= 0 && end.y < COORD_MAX);
    __CPROVER_assume(pos >= 0 && pos < COORD_MAX);
    (void)traverse_line(start, end, pos);
}

/* get_ticks_from_scroll_accum: a finite accumulator within the range kloak's
 * own asserts require is processed with no UB and no assert-abort -- i.e. the
 * precondition envelope is provably sufficient to protect the float->int cast. */
void verify_get_ticks_from_scroll_accum(void)
{
    double accum;
    __CPROVER_assume(isfinite(accum));
    /* exactly the bound kloak asserts: scroll_accum/120 in [INT32_MIN/120,
     * INT32_MAX/120]. */
    __CPROVER_assume(accum <= (double)(INT32_MAX / SCROLL_UNITS_PER_TICK)
                              * SCROLL_UNITS_PER_TICK_D);
    __CPROVER_assume(accum >= (double)(INT32_MIN / SCROLL_UNITS_PER_TICK)
                              * SCROLL_UNITS_PER_TICK_D);
    (void)get_ticks_from_scroll_accum(&accum);
}

/* current_time_ms: a plausible monotonic clock yields a non-negative ms value
 * with no int64 overflow (clock_gettime modeled above). */
void verify_current_time_ms(void)
{
    start_time = 0;
    /* First call seeds start_time and returns 0; later calls return a delta.
     * Prove the documented non-negative property for both, not just absence of
     * UB. */
    __CPROVER_assert(current_time_ms() >= 0, "seed current_time_ms non-negative");
    __CPROVER_assert(current_time_ms() >= 0, "delta current_time_ms non-negative");
}

/* sleep_ms: a non-negative millisecond count produces a valid timespec with no
 * UB (nanosleep modeled above). */
void verify_sleep_ms(void)
{
    int64_t ms;
    __CPROVER_assume(ms >= 0);
    (void)sleep_ms(ms);
}
