/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Unit tests + randomized fuzz for sdwdate's sclockadj pure arithmetic. Compiled
and run by test_sclockadj_verification.py with -I pointed at usr/src/sdwdate.
The subject's clock syscalls are never called here -- only the pure functions.
*/
#define SCLOCKADJ_TEST
#include "sclockadj.c"

#include <assert.h>
#include <stdint.h>

static void unit_split(void)
{
    time_t sec;
    long nsec;

    assert(split_ns_since_epoch(1500000000500000000LL, &sec, &nsec) == 0);
    assert(sec == 1500000000 && nsec == 500000000);

    /* Euclidean: a negative total must still yield a non-negative tv_nsec. */
    assert(split_ns_since_epoch(-1LL, &sec, &nsec) == 0);
    assert(sec == -1 && nsec == 999999999);

    assert(split_ns_since_epoch(-1000000000LL, &sec, &nsec) == 0);
    assert(sec == -1 && nsec == 0);

    assert(split_ns_since_epoch(0LL, &sec, &nsec) == 0);
    assert(sec == 0 && nsec == 0);
}

static void unit_add(void)
{
    struct timespec cur;
    struct timespec out;

    cur.tv_sec = 1000;
    cur.tv_nsec = 999999999;
    assert(timespec_add_ns(&cur, 1LL, &out) == 0);
    assert(out.tv_sec == 1001 && out.tv_nsec == 0);

    cur.tv_sec = 1000;
    cur.tv_nsec = 0;
    assert(timespec_add_ns(&cur, -1LL, &out) == 0);
    assert(out.tv_sec == 999 && out.tv_nsec == 999999999);

    /* Overflow is rejected, not UB. */
    cur.tv_sec = 9223372036LL;
    cur.tv_nsec = 0;
    assert(timespec_add_ns(&cur, 9223372036854775807LL, &out) == -1);
}

static void unit_jumps(void)
{
    unsigned long long full;
    unsigned long long rem;

    compute_jumps(5000001LL, &full, &rem);
    assert(full == 1 && rem == 1);

    compute_jumps(-5000001LL, &full, &rem);
    assert(full == 1 && rem == 1);

    compute_jumps(4999999LL, &full, &rem);
    assert(full == 0 && rem == 4999999);

    /* LLONG_MIN must not trigger llabs UB; magnitude is 2^63. */
    compute_jumps((-9223372036854775807LL - 1LL), &full, &rem);
    assert(rem < 5000000ULL);
    assert(full == 9223372036854775808ULL / 5000000ULL);
}

static void unit_parse(void)
{
    long long value;

    assert(parse_ns_arg("12345", &value) == 0 && value == 12345);
    assert(parse_ns_arg("-6789", &value) == 0 && value == -6789);
    assert(parse_ns_arg("", &value) == -1);
    assert(parse_ns_arg("12x", &value) == -1);
    assert(parse_ns_arg("  5", &value) == 0 && value == 5); /* leading ws ok */
    assert(parse_ns_arg("99999999999999999999999", &value) == -1); /* ERANGE */
}

/* xorshift64; deterministic so a failing seed is reproducible. */
static uint64_t rng_state = 0x123456789abcdef0ULL;

static long long next_ll(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (long long)rng_state;
}

static void fuzz(long iterations)
{
    long i;
    for (i = 0; i < iterations; ++i)
    {
        time_t sec;
        long nsec;
        struct timespec cur;
        struct timespec out;
        unsigned long long full;
        unsigned long long rem;
        long long total = next_ll();

        if (split_ns_since_epoch(total, &sec, &nsec) == 0)
        {
            assert(nsec >= 0 && nsec < 1000000000L);
        }

        cur.tv_sec = (time_t)next_ll();
        cur.tv_nsec =
            (long)((unsigned long long)next_ll() % 1000000000ULL);
        if (timespec_add_ns(&cur, next_ll(), &out) == 0)
        {
            assert(out.tv_nsec >= 0 && out.tv_nsec < 1000000000L);
        }

        compute_jumps(next_ll(), &full, &rem);
        assert(rem < 5000000ULL);
    }
}

int main(void)
{
    unit_split();
    unit_add();
    unit_jumps();
    unit_parse();
    fuzz(2000000L);
    printf("sclockadj harness: all assertions passed\n");
    return 0;
}
