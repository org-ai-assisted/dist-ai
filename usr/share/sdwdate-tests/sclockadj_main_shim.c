/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Linker-wrap shim for sclockadj's IMPURE main() path. Compiled WITHOUT
SCLOCKADJ_TEST together with the real usr/src/sdwdate/sclockadj.c and linked
with -Wl,--wrap=clock_gettime,--wrap=clock_settime,--wrap=sleep, so the
privileged clock syscalls and the 1s inter-step waits are intercepted -- no
root, no real clock, no waiting.

A software CLOCK_REALTIME is kept in memory; every clock_settime records the
applied delta (new - current) on stdout as "DELTA <ns>". main()'s sign
reconstruction, full-jump loop and final partial step are thereby observable
and assertable by test_sclockadj_main.py.
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* Software clock, arbitrary non-zero start. */
static struct timespec shim_clock = { 1700000000, 0 };

static long long timespec_total_ns(const struct timespec *ts)
{
    return (long long)ts->tv_sec * 1000000000LL + (long long)ts->tv_nsec;
}

int __wrap_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    (void)clk_id;
    *tp = shim_clock;
    return 0;
}

int __wrap_clock_settime(clockid_t clk_id, const struct timespec *tp)
{
    (void)clk_id;
    long long delta = timespec_total_ns(tp) - timespec_total_ns(&shim_clock);
    printf("DELTA %lld\n", delta);
    fflush(stdout);
    shim_clock = *tp;
    return 0;
}

unsigned int __wrap_sleep(unsigned int seconds)
{
    (void)seconds; /* imitate the ntpdate pacing wait with no real delay */
    return 0;
}
