/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for sdwdate's sclockadj pure arithmetic. Compiled/checked by
test_sclockadj_verification.py with -I pointed at usr/src/sdwdate. The subject's
pure functions have no loops, so CBMC proves the properties for ALL 64-bit
inputs (exhaustive, not sampled).
*/
#define SCLOCKADJ_TEST
#include "sclockadj.c"

/* split_ns_since_epoch: on success the normalised nanoseconds are in [0, 1e9). */
void verify_split_ns_since_epoch(void)
{
    long long total_ns;
    time_t sec;
    long nsec;
    if (split_ns_since_epoch(total_ns, &sec, &nsec) == 0)
    {
        __CPROVER_assert(nsec >= 0, "normalised tv_nsec is non-negative");
        __CPROVER_assert(nsec < 1000000000L, "normalised tv_nsec is < 1e9");
    }
}

/* timespec_add_ns: no signed-overflow UB (via --signed-overflow-check), and on
 * success the result tv_nsec is a valid [0, 1e9) value for clock_settime. */
void verify_timespec_add_ns(void)
{
    struct timespec cur;
    long long add_ns;
    struct timespec out;
    __CPROVER_assume(cur.tv_nsec >= 0);
    __CPROVER_assume(cur.tv_nsec < 1000000000L);
    if (timespec_add_ns(&cur, add_ns, &out) == 0)
    {
        __CPROVER_assert(out.tv_nsec >= 0, "result tv_nsec is non-negative");
        __CPROVER_assert(out.tv_nsec < 1000000000L, "result tv_nsec is < 1e9");
    }
}

/* compute_jumps: remainder strictly below the jump size; no UB even for
 * LLONG_MIN (the old llabs(LLONG_MIN) UB is gone). */
void verify_compute_jumps(void)
{
    long long ns;
    unsigned long long full_jumps;
    unsigned long long remainder;
    compute_jumps(ns, &full_jumps, &remainder);
    __CPROVER_assert(remainder < (unsigned long long)FULL_JUMP,
                     "remainder is below the fixed jump size");
}
