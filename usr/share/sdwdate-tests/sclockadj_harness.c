/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Unit tests + randomized fuzz for sdwdate's sclockadj pure arithmetic. Compiled
and run by test_sclockadj_verification.py with -I pointed at usr/src/sdwdate.
The subject's clock syscalls are never called here -- only the pure functions
step_timestamp (the bounded per-step slew) and parse_int (the CLI arg parser).
*/
#define SCLOCKADJ_TEST
#include "sclockadj.c"

#include <assert.h>
#include <stdint.h>
#include <errno.h>

#define STEP POSITIVE_STEP_NS /* +-5e6 ns per full step */

static void unit_step_two_full_and_partial(void)
{
    /* +2.5 full steps: two +STEP steps leave the remainder for a third call. */
    struct timespec ts = { .tv_sec = 100, .tv_nsec = 0 };
    int64_t shift = 2 * STEP + 1;

    assert(step_timestamp(&ts, &shift));
    assert(ts.tv_sec == 100 && ts.tv_nsec == STEP);
    assert(shift == STEP + 1);

    assert(step_timestamp(&ts, &shift));
    assert(ts.tv_sec == 100 && ts.tv_nsec == 2 * STEP);
    assert(shift == 1);

    assert(step_timestamp(&ts, &shift));
    assert(ts.tv_sec == 100 && ts.tv_nsec == 2 * STEP + 1);
    assert(shift == 0);
}

static void unit_step_negative_borrow(void)
{
    /* A negative step that underflows tv_nsec borrows one second, staying
     * normalised. */
    struct timespec ts = { .tv_sec = 100, .tv_nsec = 2000000 };
    int64_t shift = NEGATIVE_STEP_NS;

    assert(step_timestamp(&ts, &shift));
    assert(ts.tv_sec == 99 && ts.tv_nsec == 997000000L);
    assert(shift == 0);
}

static void unit_step_positive_carry(void)
{
    /* A positive step that overflows tv_nsec carries one second. */
    struct timespec ts = { .tv_sec = 100, .tv_nsec = 999000000L };
    int64_t shift = STEP;

    assert(step_timestamp(&ts, &shift));
    assert(ts.tv_sec == 101 && ts.tv_nsec == 4000000L);
    assert(shift == 0);
}

static void unit_step_overflow_guarded(void)
{
    /* The sec carry at INT64_MAX and borrow at INT64_MIN are rejected, not UB. */
    struct timespec hi = { .tv_sec = (time_t)INT64_MAX, .tv_nsec = 999000000L };
    int64_t up = STEP;
    assert(!step_timestamp(&hi, &up));

    struct timespec lo = { .tv_sec = (time_t)INT64_MIN, .tv_nsec = 2000000 };
    int64_t down = NEGATIVE_STEP_NS;
    assert(!step_timestamp(&lo, &down));
}

static void unit_step_null(void)
{
    struct timespec ts = { 0 };
    int64_t shift = 1;
    assert(!step_timestamp(NULL, &shift));
    assert(!step_timestamp(&ts, NULL));
}

static void unit_parse(void)
{
    errno = 0;
    assert(parse_int("12345") == 12345 && errno == 0);
    errno = 0;
    assert(parse_int("-6789") == -6789 && errno == 0);
    errno = 0;
    assert(parse_int("  5") == 5 && errno == 0); /* strtoll skips leading ws */

    /* Trailing garbage, non-numeric and out-of-range each flag errno. */
    errno = 0;
    (void)parse_int("12x");
    assert(errno != 0);
    errno = 0;
    (void)parse_int("abc");
    assert(errno != 0);
    errno = 0;
    (void)parse_int("99999999999999999999999"); /* ERANGE from strtoll */
    assert(errno != 0);
}

/* xorshift64; deterministic so a failing seed is reproducible. */
static uint64_t rng_state = 0x123456789abcdef0ULL;

static int64_t next_ll(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (int64_t)rng_state;
}

/* Single-step invariants for arbitrary (valid timespec, 64-bit shift): no bad
 * tv_nsec reaches clock_settime, the step is bounded, and the budget moves
 * strictly toward zero (loop progress). */
static void fuzz_single(long iterations)
{
    long i;
    for (i = 0; i < iterations; ++i)
    {
        struct timespec ts;
        int64_t shift = next_ll();
        int64_t before = shift;
        int64_t applied;

        ts.tv_sec = (time_t)next_ll();
        ts.tv_nsec = (long)((uint64_t)next_ll() % 1000000000ULL);

        if (!step_timestamp(&ts, &shift))
            continue; /* INT64_MAX/MIN sec guard -- rejected, not UB */

        assert(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L);

        applied = before - shift;
        assert(applied <= STEP && applied >= NEGATIVE_STEP_NS);

        if (before > 0)
            assert(shift >= 0 && shift < before);
        else if (before < 0)
            assert(shift <= 0 && shift > before);
        else
            assert(shift == 0);
    }
}

/* Full slew loop for bounded budgets: it terminates and the applied steps sum
 * to exactly the requested shift (conservation across the loop). */
static void fuzz_loop(long iterations)
{
    long i;
    for (i = 0; i < iterations; ++i)
    {
        struct timespec ts;
        int64_t shift = next_ll() % (10 * STEP + 1); /* up to ~10 steps */
        int64_t remaining = shift;
        long long applied_total = 0;
        long steps = 0;

        ts.tv_sec = (time_t)(next_ll() % 1000000000LL);
        ts.tv_nsec = (long)((uint64_t)next_ll() % 1000000000ULL);

        while (remaining != 0)
        {
            int64_t before = remaining;
            assert(step_timestamp(&ts, &remaining)); /* small sec, no guard */
            assert(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L);
            applied_total += (before - remaining);
            assert(++steps <= 11); /* 10*STEP budget -> <= 11 steps */
        }
        assert(applied_total == (long long)shift);
    }
}

int main(void)
{
    unit_step_two_full_and_partial();
    unit_step_negative_borrow();
    unit_step_positive_carry();
    unit_step_overflow_guarded();
    unit_step_null();
    unit_parse();
    fuzz_single(2000000L);
    fuzz_loop(200000L);
    printf("sclockadj harness: all assertions passed\n");
    return 0;
}
