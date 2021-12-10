/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#include "udp_base.h"

class udp_socket : public udp_base {
};

/**
 * @test udp_socket.ti_1_ipv4
 * @brief
 *    Create IPv4 UDP socket
 * @details
 */
TEST_F(udp_socket, ti_1_ipv4)
{
    int fd;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    EXPECT_LE(0, fd);
    EXPECT_EQ(errno, EOK);

    close(fd);
}

/**
 * @test udp_socket.ti_6_ipv6
 * @brief
 *    Create IPv6 UDP socket
 * @details
 */
TEST_F(udp_socket, ti_2_ipv6)
{
    int fd;

    fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
    EXPECT_LE(0, fd);
    EXPECT_EQ(errno, EOK);

    close(fd);
}
