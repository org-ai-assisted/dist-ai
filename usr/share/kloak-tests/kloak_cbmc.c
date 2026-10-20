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
pure functions are loop-free, so the geometry/scroll/time proofs are exhaustive;
random_between's rejection loop is bounded (see its note).

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

/* check_point_in_area: for in-envelope rectangles the result is EXACTLY the
 * containment predicate, with no arithmetic UB. */
void verify_check_point_in_area(void)
{
    int32_t x, y, rx, ry, rw, rh;
    __CPROVER_assume(x >= 0 && x < COORD_MAX);
    __CPROVER_assume(y >= 0 && y < COORD_MAX);
    __CPROVER_assume(rx >= 0 && rx < COORD_MAX);
    __CPROVER_assume(ry >= 0 && ry < COORD_MAX);
    __CPROVER_assume(rw >= 0 && rw < COORD_MAX);
    __CPROVER_assume(rh >= 0 && rh < COORD_MAX);
    bool got = check_point_in_area(x, y, rx, ry, rw, rh);
    bool want = (x >= rx && x < rx + rw && y >= ry && y < ry + rh);
    __CPROVER_assert(got == want, "containment predicate is exact");
}

/* check_screen_touch: for in-envelope geometries the touch test is UB-free (the
 * +1/+2 grows and corner sums cannot overflow). */
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

/* traverse_line: for in-envelope endpoints and a forward step the walk is
 * UB-free (coordinate adds and the double->int32 step cast stay in range). */
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
