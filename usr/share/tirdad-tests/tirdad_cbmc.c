/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for tirdad's RECENT TCP ISN hook path (the u64
secure_tcp_seq_and_ts_off livepatch variant). Compiled/checked by
test_tirdad_verification.py with -I pointed at the shiminc/ kernel shim and at
the real module/ directory, so the subject here is the actual, unmodified
module/tirdad.c -- no synthetic copy. The hook functions are loop-free, so CBMC
proves the properties for ALL inputs (exhaustive, not sampled).
*/
#include <linux/init.h>
#include "tirdad.c"

/* Faithful model of the kernel RNG: fill the buffer with nondeterministic
 * bytes. The proofs below must hold for every possible draw. */
void get_random_bytes(void *buf, int nbytes) { __CPROVER_havoc_slice(buf, (size_t)nbytes); }
int  wait_for_random_bytes(void) { return 0; }

unsigned int   nondet_u32(void);
unsigned short nondet_u16(void);

/* Union ABI: seq occupies the low 32 bits and ts_off the high 32 bits of
 * hash64, matching the kernel's secure_tcp_seq_and_ts_off u64 contract (the
 * kernel reads the sequence number as (u32)ret and the timestamp offset as
 * (u32)(ret >> 32)) on this target's endianness. */
void verify_union_layout(void)
{
    union tcp_seq_and_ts_off u;
    u.seq = nondet_u32();
    u.ts_off = nondet_u32();
    __CPROVER_assert((u.hash64 & 0xffffffffULL) == u.seq,
                     "low 32 bits of hash64 are the sequence number");
    __CPROVER_assert(((u.hash64 >> 32) & 0xffffffffULL) == u.ts_off,
                     "high 32 bits of hash64 are the timestamp offset");
}

/* Core property: when the kernel has TCP timestamps disabled, tirdad must not
 * emit a nonzero timestamp offset -- the high 32 bits of the returned ISN word
 * stay zero, so tirdad does not re-introduce a fingerprinting surface the
 * kernel has switched off. */
void verify_ts_off_zero_when_disabled(void)
{
    struct net net;
    __CPROVER_assume(net.ipv4.sysctl_tcp_timestamps != 1);
    u64 ret = get_isn_ts(&net);
    __CPROVER_assert(((ret >> 32) & 0xffffffffULL) == 0,
                     "ts_off is zero when TCP timestamps disabled");
}

/* Same property through the exported IPv4 hook the kernel actually calls; the
 * address/port arguments are ignored and must not change the outcome. */
void verify_hook_v4_ts_off_zero(void)
{
    struct net net;
    __be32 saddr = nondet_u32(), daddr = nondet_u32();
    __be16 sport = nondet_u16(), dport = nondet_u16();
    __CPROVER_assume(net.ipv4.sysctl_tcp_timestamps != 1);
    u64 ret = secure_tcp_seq_and_ts_off_hooked(&net, saddr, daddr, sport, dport);
    __CPROVER_assert(((ret >> 32) & 0xffffffffULL) == 0,
                     "v4 hook: ts_off zero when TCP timestamps disabled");
}

/* Same property through the exported IPv6 hook. */
void verify_hook_v6_ts_off_zero(void)
{
    struct net net;
    __be32 saddr[4], daddr[4];
    __be16 sport = nondet_u16(), dport = nondet_u16();
    __CPROVER_assume(net.ipv4.sysctl_tcp_timestamps != 1);
    u64 ret = secure_tcpv6_seq_and_ts_off_hooked(&net, saddr, daddr, sport, dport);
    __CPROVER_assert(((ret >> 32) & 0xffffffffULL) == 0,
                     "v6 hook: ts_off zero when TCP timestamps disabled");
}
