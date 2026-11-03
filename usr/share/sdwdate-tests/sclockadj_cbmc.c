/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for sdwdate's sclockadj pure arithmetic. Compiled/checked by
test_sclockadj_verification.py with -I pointed at usr/src/sdwdate. step_timestamp
is loop-free, so CBMC proves the properties for ALL 64-bit inputs (exhaustive,
not sampled) -- the function is fed numbers derived from untrusted network time.
*/
#define SCLOCKADJ_TEST
#include "sclockadj.c"

/* step_timestamp applies ONE bounded slew step to a valid timespec. Proven for
 * every input:
 *   - no signed-overflow / conversion UB in the ns/sec arithmetic (the sec
 *     carry/borrow is guarded at INT64_MAX/MIN, returning false instead);
 *   - on success the result tv_nsec is normalised to [0, NS_IN_SEC) -- the value
 *     handed to clock_settime;
 *   - the amount removed from the remaining shift is bounded by the fixed step
 *     size, and the remaining shift moves strictly toward zero, so the
 *     slew_system_time loop that calls this always terminates. */
void verify_step_timestamp(void)
{
    struct timespec ts;
    int64_t shift;
    int64_t in_shift;
    int64_t applied;

    /* Precondition the subject documents and asserts: a normalised timespec. */
    __CPROVER_assume(ts.tv_nsec >= 0);
    __CPROVER_assume(ts.tv_nsec < NS_IN_SEC);

    in_shift = shift;

    if (step_timestamp(&ts, &shift))
    {
        __CPROVER_assert(ts.tv_nsec >= 0,
                         "result tv_nsec is non-negative");
        __CPROVER_assert(ts.tv_nsec < NS_IN_SEC,
                         "result tv_nsec is < NS_IN_SEC");

        /* Amount the clock moved == amount removed from the budget, bounded. */
        applied = in_shift - shift;
        __CPROVER_assert(applied <= POSITIVE_STEP_NS,
                         "applied step is <= +POSITIVE_STEP_NS");
        __CPROVER_assert(applied >= NEGATIVE_STEP_NS,
                         "applied step is >= NEGATIVE_STEP_NS");

        /* Termination: a non-zero budget strictly shrinks toward zero. */
        if (in_shift > 0)
            __CPROVER_assert(shift >= 0 && shift < in_shift,
                             "positive budget strictly decreases toward zero");
        else if (in_shift < 0)
            __CPROVER_assert(shift <= 0 && shift > in_shift,
                             "negative budget strictly increases toward zero");
        else
            __CPROVER_assert(shift == 0, "zero budget stays zero");
    }
}
