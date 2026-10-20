/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC kernel-header shim for the tirdad livepatch module. The real
module/tirdad.c is #included verbatim by tirdad_cbmc.c (no synthetic copy, no
upstream edit), so the kernel headers it pulls must resolve to these fakes: a
minimal, CBMC-parsable surface for exactly the types, macros and symbols
tirdad.c touches -- nothing kernel-specific CBMC cannot model.

This is the single source; the other fake kernel/net headers just include it.
It pins LINUX_VERSION_CODE to select tirdad's RECENT hook path (the u64
secure_tcp_seq_and_ts_off variant), which is the only path under test.
*/
#ifndef TIRDAD_CBMC_SHIM_H
#define TIRDAD_CBMC_SHIM_H
#include <stdarg.h>
#include <stddef.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef u32 __be32;
typedef u16 __be16;

int snprintf(char *, size_t, const char *, ...);
int vprintk(const char *, va_list);

/* KERNEL_VERSION/LINUX_VERSION_CODE: pick the RECENT branch of tirdad.c, i.e.
 * LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 17). */
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 18, 17)

#define IS_ENABLED(opt) 1
#define CONFIG_IPV6 1

/* struct net: tirdad reads only net->ipv4.sysctl_tcp_timestamps. */
struct net_ipv4 { int sysctl_tcp_timestamps; };
struct net { struct net_ipv4 ipv4; };
#define READ_ONCE(x) (x)

void get_random_bytes(void *buf, int nbytes);
int  wait_for_random_bytes(void);

/* livepatch: only the struct shapes tirdad's static initializers reference. */
struct module;
struct klp_func   { const char *old_name; void *new_func; };
struct klp_object { struct klp_func *funcs; };
struct klp_patch  { struct module *mod; struct klp_object *objs; };
int klp_enable_patch(struct klp_patch *);
#define THIS_MODULE ((struct module *)0)

/* Module registration glue is irrelevant to the proofs -> no-ops. */
#define module_init(x)
#define module_exit(x)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_INFO(a, b)
#endif
