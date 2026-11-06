/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for the pure arithmetic in kloak's sandboxed Wayland adapter
(src/kloakwl.c), resolved via KLOAK_REPO. No kloakwl source change: reuses the
KLOAK_FUZZING seam (guards out main()), so the actual function bodies are
verified.

CBMC 6.x enables the full standard check set by default (signed/unsigned/pointer/
float overflow, conversion, nan, bounds, pointer, div-by-zero), so each verify_*
below is proven free of ALL of those for EVERY input in the assumed envelope. The
geometry/scroll/time proofs are loop-free and exhaustive; the bounded loops
(random_between's rejection sampling, traverse_line's Bresenham walk) run under
--unwind.

Each verify_* assumes kloak's real operating envelope (screen coordinates well
below INT32_MAX, never adversarial INT64 extremes) and then proves the function's
invariant. Outside the envelope kloak relies on -ftrapv to turn an overflow into
a safe crash+restart (by design), which is not a property this suite asserts.

The libc boundary (read for /dev/urandom, clock_gettime) is modeled here so the
proofs are deterministic -- environment shims, not reimplementations of kloak
logic.
*/
#define KLOAK_FUZZING
/* glibc's isfinite() expands to __builtin_isfinite, which CBMC has no body for.
 * Route the builtin to an IEEE arithmetic finite test -- x-x is 0 only for a
 * finite x (NaN-NaN and Inf-Inf are NaN). CBMC's float model handles it. */
#define __builtin_isfinite(x) (((x) - (x)) == 0.0)
#include "kloakwl.c"

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
    /* Model CLOCK_MONOTONIC faithfully: a non-decreasing timespec. Havoc a FRESH
     * nondet sample (as the read() stub does), THEN constrain it -- order matters.
     * clock_gettime is an output-parameter function, so a constrain-without-write
     * leaves the caller's zero-initialised struct, i.e. the all-zeros clock that
     * made this proof vacuous. The constraints are the clock's real contract:
     * tv_nsec normalised, and monotonic non-decreasing across calls (tv_sec rises,
     * or tv_sec is equal and tv_nsec does not fall) -- the property current_time_ms
     * relies on for its non-negative delta. A static carries the prior reading.
     * Constraining the raw timespec (not a derived ms) is both the exact
     * CLOCK_MONOTONIC guarantee and far cheaper for the solver than reconciling a
     * second symbolic multiply here against timespec_to_ms's. The tv_sec bound
     * (1LL<<25, ~388 days) is kloak's real operating envelope, as COORD_MAX is for
     * geometry: a maintained Whonix/Kicksecure host reboots for security updates
     * far sooner, tv_sec*1000 cannot overflow int64 until ~292 million years
     * regardless, and adversarial extremes rely on -ftrapv (see top). */
    static int64_t prev_sec = 0, prev_nsec = 0;
    __CPROVER_havoc_object(tp);
    __CPROVER_assume(tp->tv_sec >= prev_sec && tp->tv_sec < (1LL << 25));
    __CPROVER_assume(tp->tv_nsec >= 0 && tp->tv_nsec < 1000000000L);
    __CPROVER_assume(tp->tv_sec > prev_sec || tp->tv_nsec >= prev_nsec);
    prev_sec = tp->tv_sec;
    prev_nsec = tp->tv_nsec;
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
 * origin plus the local offset (the inverse of the above). Validity is now
 * reported through out_is_valid (the (-1,-1) sentinel is gone, since negative
 * coordinates are legal). */
void verify_screen_local_coord_to_abs_coord(void)
{
    struct output_geometry g;
    int32_t x, y, idx;
    struct coord c;
    bool is_valid;
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
    c = screen_local_coord_to_abs_coord(x, y, idx, &is_valid);
    if (is_valid) {
        __CPROVER_assert(c.x == g.x + x, "abs x = origin + local x");
        __CPROVER_assert(c.y == g.y + y, "abs y = origin + local y");
    }
    for (i = 0; i < MAX_SCREEN_COUNT; i++) {
        state.output_geometries[i] = NULL;
    }
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
    /* read_random reads the fixed CHILD_FD_URANDOM fd, which the read() model
     * above satisfies -- no fd global to seed. */
    r = random_between(lower, upper);
    __CPROVER_assert(r >= lower, "result not below lower bound");
    __CPROVER_assert(r <= upper, "result not above upper bound");
}

/* traverse_line: for in-envelope endpoints and a forward step the Bresenham
 * walk is UB-free (the error-term and coordinate adds stay in range). Success is
 * now reported through out_success (the (-1,-1) end-of-line sentinel is gone). */
void verify_traverse_line(void)
{
    struct coord start, end;
    int32_t pos;
    bool out_success;
    __CPROVER_assume(start.x >= 0 && start.x < COORD_MAX);
    __CPROVER_assume(start.y >= 0 && start.y < COORD_MAX);
    __CPROVER_assume(end.x >= 0 && end.x < COORD_MAX);
    __CPROVER_assume(end.y >= 0 && end.y < COORD_MAX);
    __CPROVER_assume(pos >= 0 && pos < COORD_MAX);
    (void)traverse_line(start, end, pos, &out_success);
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
