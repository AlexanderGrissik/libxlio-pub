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

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"
#include "udp_base.h"

class udp_send : public udp_base {
};

/**
 * @test udp_send.ti_1
 * @brief
 *    send() successful call
 * @details
 */
TEST_F(udp_send, ti_1)
{
    int rc = EOK;
    int fd;
    char buf[] = "hello";

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = send(fd, (void *)buf, sizeof(buf), 0);
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(sizeof(buf), static_cast<size_t>(rc));

    close(fd);
}

/**
 * @test udp_send.ti_2
 * @brief
 *    send() invalid socket fd
 * @details
 */
TEST_F(udp_send, ti_2)
{
    int rc = EOK;
    int fd;
    char buf[] = "hello";

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = send(0xFF, (void *)buf, sizeof(buf), 0);
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(-1, rc);

    close(fd);
}

/**
 * @test udp_send.ti_3
 * @brief
 *    send() invalid buffer length (>65,507 bytes, >65,527 bytes IPv6)
 * @details
 */
TEST_F(udp_send, ti_3)
{
    int rc = EOK;
    int fd;
    char buf[65528] = "hello";
    size_t max_possible_size = (client_addr.addr.sa_family == AF_INET ? 65507 : 65527);

    SKIP_TRUE((client_addr.addr.sa_family == AF_INET),
              "IPv6 Fragmentation is currently unsupported");

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = send(fd, (void *)buf, max_possible_size, 0);
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(max_possible_size, static_cast<size_t>(rc));

    errno = EOK;
    rc = send(fd, (void *)buf, sizeof(buf), 0);
    EXPECT_EQ(EMSGSIZE, errno);
    EXPECT_EQ(-1, rc);

    close(fd);
}

/**
 * @test udp_send.ti_4
 * @brief
 *    send() invalid address length
 * @details
 */
TEST_F(udp_send, ti_4)
{
    int rc = EOK;
    int fd;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr) - 1);
    EXPECT_EQ(EINVAL, errno);
    EXPECT_EQ(-1, rc);

    close(fd);
}

/**
 * @test udp_send.ti_5
 * @brief
 *    send() invalid flag set (MSG_OOB for TCP only)
 * @details
 */
TEST_F(udp_send, ti_5)
{
    int rc = EOK;
    int fd;
    char buf[] = "hello";

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = send(fd, (void *)buf, sizeof(buf), MSG_OOB);
    if (m_family == PF_INET) {
        EXPECT_EQ(EOPNOTSUPP, errno);
        EXPECT_EQ(-1, rc);
    } else {
        // Apparently IPv6 ignores MSG_OOB
        EXPECT_EQ(EOK, errno);
        EXPECT_EQ(sizeof(buf), static_cast<size_t>(rc));
    }

    close(fd);
}

/**
 * @test udp_send.ti_6
 * @brief
 *    send() to zero port
 * @details
 */
TEST_F(udp_send, ti_6)
{
    int rc = EOK;
    int fd;
    char buf[] = "hello";
    sockaddr_store_t addr;

    fd = udp_base::sock_create();
    ASSERT_LE(0, fd);

    errno = EOK;
    rc = bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    memcpy(&addr, &server_addr, sizeof(addr));
    sys_set_port((struct sockaddr *)&addr, 0);

    errno = EOK;
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(0, rc);

    errno = EOK;
    rc = send(fd, (void *)buf, sizeof(buf), 0);
    EXPECT_EQ(EOK, errno);
    EXPECT_EQ(sizeof(buf), static_cast<size_t>(rc));

    close(fd);
}

/**
 * @test udp_send.mapped_ipv4_send
 * @brief
 *    IPv6 mapped IPv4 send
 *
 * @details
 */
TEST_F(udp_send, mapped_ipv4_send)
{
    if (!is_mapped_ipv4_set()) {
        return;
    }

    int pid = fork();
    if (0 == pid) { // Child
        int fd = udp_base::sock_create(AF_INET6, false);
        EXPECT_LE_ERRNO(0, fd);
        if (0 > fd) {
            exit(testing::Test::HasFailure());
            return;
        }

        auto do_send = [=](sa_family_t family) {
            sockaddr_store_t &cl_server_t =
                (family == AF_INET ? server_addr_mapped_ipv4 : server_addr);

            struct sockaddr *sr_addr = &cl_server_t.addr;

            barrier_fork(pid);

            char buffer[8] = {0};
            sendto(fd, buffer, sizeof(buffer), 0, sr_addr, sizeof(cl_server_t));

            iovec vec = {.iov_base = buffer, .iov_len = sizeof(buffer)};
            msghdr msg;
            msg.msg_iov = &vec;
            msg.msg_iovlen = 1U;
            msg.msg_name = sr_addr;
            msg.msg_namelen = sizeof(cl_server_t);
            msg.msg_control = nullptr;
            msg.msg_controllen = 0;
            sendmsg(fd, &msg, 0);

            mmsghdr mmsg;
            mmsg.msg_hdr = msg;
            mmsg.msg_len = 0U;
            sendmmsg(fd, &mmsg, 1, 0);
        };

        do_send(AF_INET);
        do_send(AF_INET6);

        close(fd);

        // This exit is very important, otherwise the fork
        // keeps running and may duplicate other tests.
        exit(testing::Test::HasFailure());
    } else { // Parent
        auto do_recv = [pid, this](sa_family_t family) {
            (void)family;
            int fd = udp_base::sock_create(AF_INET6, false, 10);
            EXPECT_LE_ERRNO(0, fd);
            if (0 <= fd) {
                sockaddr_store_t any_addr;
                memset(&any_addr, 0, sizeof(any_addr));
                any_addr.addr6.sin6_family = AF_INET6;
                any_addr.addr6.sin6_port = server_addr.addr6.sin6_port;

                int rc = bind(fd, &any_addr.addr, sizeof(sockaddr_store_t));
                EXPECT_EQ_ERRNO(0, rc);
                if (0 == rc) {
                    barrier_fork(pid);

                    char buffer[8];
                    rc = recv(fd, buffer, sizeof(buffer), 0);
                    EXPECT_EQ(8, rc);
                    rc = recv(fd, buffer, sizeof(buffer), 0);
                    EXPECT_EQ(8, rc);
                    rc = recv(fd, buffer, sizeof(buffer), 0);
                    EXPECT_EQ(8, rc);
                }

                close(fd);
            }
        };

        do_recv(AF_INET);
        do_recv(AF_INET6);

        EXPECT_EQ(0, wait_fork(pid));
    }
}
