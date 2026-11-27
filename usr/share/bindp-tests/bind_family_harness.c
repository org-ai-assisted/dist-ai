/*
   Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions.

   AI-Assisted

   Test fixture for the bindp-tests suite (NOT a copy of the subject). Exercises
   bindp's setsockopt gate through the REAL libindp.so (LD_PRELOAD by the test):

     - two IPv4 UDP sockets,
     - bound to the SAME wildcard port via a sockaddr whose sa_family is
       AF_UNSPEC (Linux accepts AF_UNSPEC + INADDR_ANY as an IPv4 wildcard bind),
     - with REUSE_ADDR / REUSE_PORT requested from bindp.

   bindp must apply SO_REUSEADDR / SO_REUSEPORT to BOTH sockets for the second
   bind to succeed. If bindp keys the option gate on the caller's sa_family
   (AF_UNSPEC) instead of the socket's real family, it skips the options and the
   second bind fails EADDRINUSE -- the regression this harness detects.

   Exit codes:
     0  both binds succeeded (options applied to the AF_UNSPEC path)
     1  second bind rejected (the regression)
     2  setup failure (socket / first bind / getsockname), not an assertion
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static void fill(struct sockaddr_in *sa, in_port_t port) {
    memset(sa, 0, sizeof(*sa));
    /* Deliberately AF_UNSPEC, not AF_INET: a valid IPv4 wildcard bind on Linux. */
    sa->sin_family = AF_UNSPEC;
    sa->sin_addr.s_addr = htonl(INADDR_ANY);
    sa->sin_port = port;
}

int main(void) {
    int s1 = socket(AF_INET, SOCK_DGRAM, 0);
    int s2 = socket(AF_INET, SOCK_DGRAM, 0);
    if (s1 < 0 || s2 < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 2;
    }

    struct sockaddr_in first;
    fill(&first, 0);
    if (bind(s1, (struct sockaddr *)&first, sizeof(first)) != 0) {
        fprintf(stderr, "first bind failed: %s\n", strerror(errno));
        return 2;
    }

    struct sockaddr_in got;
    socklen_t got_len = sizeof(got);
    if (getsockname(s1, (struct sockaddr *)&got, &got_len) != 0) {
        fprintf(stderr, "getsockname: %s\n", strerror(errno));
        return 2;
    }

    struct sockaddr_in second;
    fill(&second, got.sin_port);
    if (bind(s2, (struct sockaddr *)&second, sizeof(second)) != 0) {
        fprintf(stderr, "second bind failed: %s\n", strerror(errno));
        return 1;
    }

    printf("ok port=%d\n", ntohs(got.sin_port));
    return 0;
}
