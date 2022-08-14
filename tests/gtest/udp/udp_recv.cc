/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/mman.h>
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "src/vma/util/sock_addr.h"
#include "udp_base.h"

#define EXPECT_EQ_ADDR(v_peer, v_mapped, v_6)                                                      \
    DO_WHILE0(                                                                                     \
        if (family == AF_INET) { EXPECT_EQ_MAPPED_IPV4((v_peer), (v_mapped)); } else {             \
            EXPECT_EQ_IPV6((v_peer), (v_6));                                                       \
        })

class udp_recv : public udp_base {
};

/**
 * @test udp_recv.mapped_ipv4_recv
 * @brief
 *    IPv6 mapped IPv4 receive
 *
 * @details
 */
TEST_F(udp_recv, mapped_ipv4_recv)
{
    if (!is_mapped_ipv4_set()) {
        return;
    }

    int pid = fork();

    if (0 == pid) { // Child
        barrier_fork(pid);

        auto do_send = [this](sa_family_t family) {
            int fd = udp_base::sock_create_fa(family, false);
            EXPECT_LE_ERRNO(0, fd);
            if (0 <= fd) {
                sockaddr_store_t &cl_client_t =
                    (family == AF_INET ? client_addr_mapped_ipv4 : client_addr);
                sockaddr_store_t &cl_server_t =
                    (family == AF_INET ? server_addr_mapped_ipv4 : server_addr);
                struct sockaddr *cl_addr = &cl_client_t.addr;
                struct sockaddr *sr_addr = &cl_server_t.addr;

                int rc = bind(fd, cl_addr, sizeof(cl_client_t));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    rc = connect(fd, sr_addr, sizeof(cl_server_t));
                    EXPECT_EQ_ERRNO(0, rc);
                    if (0 == rc) {
                        log_trace("Established connection: fd=%d to %s from %s\n", fd,
                                  SOCK_STR(cl_server_t), SOCK_STR(cl_client_t));

                        char buffer[8] = {0};
                        send(fd, buffer, sizeof(buffer), 0);
                        send(fd, buffer, sizeof(buffer), 0);
                        send(fd, buffer, sizeof(buffer), 0);
#if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function && defined HAVE___RECVFROM_CHK
                        send(fd, buffer, sizeof(buffer), 0);
#endif
                    }
                }

                close(fd);
            }
        };

        do_send(AF_INET6);
        do_send(AF_INET);

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { // Parent
        sockaddr_store_t any_addr;
        memset(&any_addr, 0, sizeof(any_addr));
        any_addr.addr6.sin6_family = AF_INET6;
        any_addr.addr6.sin6_port = server_addr.addr6.sin6_port;

        int fd = udp_base::sock_create_to(AF_INET6, false, 10);
        EXPECT_LE_ERRNO(0, fd);
        if (0 <= fd) {
            int rc = bind(fd, &any_addr.addr, sizeof(any_addr));
            EXPECT_EQ_ERRNO(0, rc);
            if (0 == rc) {
                barrier_fork(pid);

                sockaddr_store_t peer_addr;
                struct sockaddr *ppeer = &peer_addr.addr;
                socklen_t socklen = sizeof(peer_addr);
                memset(&peer_addr, 0, socklen);

                char buffer[8];
                auto clear_sockaddr = [&socklen, &peer_addr]() {
                    socklen = sizeof(peer_addr);
                    memset(&peer_addr, 0, socklen);
                };

                auto do_recv = [&](sa_family_t family) {
                    clear_sockaddr();
                    recvfrom(fd, buffer, sizeof(buffer), 0, ppeer, &socklen);
                    EXPECT_EQ_ADDR(peer_addr.addr6, client_addr_mapped_ipv4.addr4.sin_addr.s_addr,
                                   client_addr.addr6);

#if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function && defined HAVE___RECVFROM_CHK
                    clear_sockaddr();
                    __recvfrom_chk(fd, buffer, sizeof(buffer), sizeof(buffer), 0, ppeer, &socklen);
                    EXPECT_EQ_ADDR(peer_addr.addr6, client_addr_mapped_ipv4.addr4.sin_addr.s_addr,
                                   client_addr.addr6);
#endif // HAVE___RECVFROM_CHK

                    clear_sockaddr();
                    iovec vec = {.iov_base = buffer, .iov_len = sizeof(buffer)};
                    msghdr msg;
                    msg.msg_iov = &vec;
                    msg.msg_iovlen = 1U;
                    msg.msg_name = ppeer;
                    msg.msg_namelen = socklen;
                    msg.msg_control = nullptr;
                    msg.msg_controllen = 0;
                    recvmsg(fd, &msg, 0);
                    EXPECT_EQ_ADDR(peer_addr.addr6, client_addr_mapped_ipv4.addr4.sin_addr.s_addr,
                                   client_addr.addr6);

                    clear_sockaddr();
                    mmsghdr mmsg;
                    mmsg.msg_hdr = msg;
                    mmsg.msg_len = 0;
                    recvmmsg(fd, &mmsg, 1, 0, nullptr);
                    EXPECT_EQ_ADDR(peer_addr.addr6, client_addr_mapped_ipv4.addr4.sin_addr.s_addr,
                                   client_addr.addr6);
                };

                do_recv(AF_INET6);
                do_recv(AF_INET);
            }

            close(fd);
        }

        EXPECT_EQ(0, wait_fork(pid));
    }
}
