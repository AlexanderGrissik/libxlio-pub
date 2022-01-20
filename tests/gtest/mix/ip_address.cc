/*
 * Copyright (c) 2001-2022 Mellanox Technologies, Ltd. All rights reserved.
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

#include "mix_base.h"
#include "src/vma/util/ip_address.h"

#define SOCKLEN4 static_cast<socklen_t>(sizeof(sockaddr_in))
#define SOCKLEN6 static_cast<socklen_t>(sizeof(sockaddr_in6))

class ip_address_test : public mix_base {
public:
    typedef union {
        in_addr m_1;
        in_addr_t m_2;
    } ip_v4;

    typedef union {
        in6_addr m_1;
        uint64_t m_2[2];
    } ip_v6;

    ip_v4 m_addr4;
    ip_v6 m_addr6;

    ip_address_test()
    {
        m_addr4.m_2 = 0xAAAA9999;
        m_addr6.m_2[0] = 0xEEEEEEEE99999999;
        m_addr6.m_2[1] = 0x99999999EEEEEEEE;
    }
};

TEST_F(ip_address_test, ip_address_ctors)
{
    ip_address sa2_4(m_addr4.m_2);
    in_addr_t temp = sa2_4.get_in_addr();
    EXPECT_EQ(0, memcmp(&temp, &m_addr4, sizeof(m_addr4)));
    ip_address sa1_4(m_addr4.m_1);
    EXPECT_EQ(0, memcmp(&sa1_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    ip_address sa1_6(m_addr6.m_1);
    EXPECT_EQ(0, memcmp(&sa1_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));

    ip_address sa3_4(sa1_4);
    EXPECT_EQ(0, memcmp(&sa3_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    ip_address sa3_6(sa1_6);
    EXPECT_EQ(0, memcmp(&sa3_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));

    ip_address sa4_4(std::move(sa3_4));
    EXPECT_EQ(0, memcmp(&sa4_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(0, memcmp(&sa3_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    ip_address sa4_6(std::move(sa3_6));
    EXPECT_EQ(0, memcmp(&sa4_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(0, memcmp(&sa3_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
}

TEST_F(ip_address_test, ip_address_getters)
{
    ip_address sa1_4(m_addr4.m_1);
    ip_address sa1_6(m_addr6.m_1);

    EXPECT_FALSE(sa1_4.is_mc());
    EXPECT_FALSE(sa1_6.is_mc());

    ip_address sa2_4(sa1_4);
    ip_address sa2_6(sa1_6);
    EXPECT_TRUE(sa1_4 == sa2_4);
    EXPECT_TRUE(sa1_6 == sa2_6);

    ip_v4 addr4_2;
    ip_v6 addr6_2;
    addr4_2.m_2 = 0x9999AAAA;
    addr6_2.m_2[0] = 0x99999999EEEEEEEE;
    addr6_2.m_2[1] = 0xEEEEEEEE99999999;
    ip_address sa3_4(addr4_2.m_1);
    ip_address sa3_6(addr6_2.m_1);
    EXPECT_TRUE(sa2_4 != sa3_4);
    EXPECT_TRUE(sa2_6 != sa3_6);
    EXPECT_TRUE(sa3_4 != sa3_6);

    // EXPECT_EQ(11ULL, sa1_4.hash());
    // EXPECT_EQ(199ULL, sa1_6.hash());

    // Test garbage space to be nullified in case of IPv4.
    ip_v6 addr6_4 = {.m_2 = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}};
    ip_address sa4_4(addr6_4.m_1);
    ip_address sa5_4(addr6_2.m_1);
    EXPECT_TRUE(sa4_4 != sa5_4);
    new (&sa4_4) ip_address(m_addr4.m_1);
    new (&sa5_4) ip_address(m_addr4.m_1);
    EXPECT_TRUE(sa4_4 == sa5_4);
}

TEST_F(ip_address_test, ip_address_setters)
{
    ip_address sa1(m_addr4.m_1);

    ip_v4 addr4_1;
    ip_v6 addr6_1;
    addr4_1.m_2 = 0x010404E0;
    addr6_1.m_2[0] = 0xAAAAAAAA000000FF;
    addr6_1.m_2[1] = 0x0;

    sa1 = ip_address(addr6_1.m_1);
    EXPECT_EQ(0, memcmp(&sa1.get_in6_addr(), &addr6_1, sizeof(addr6_1)));
    // EXPECT_TRUE(sa1.is_mc());
    sa1 = ip_address(addr4_1.m_1);
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    EXPECT_TRUE(sa1.is_mc());

    ip_address sa2(addr4_1.m_1);
    sa1 = ip_address(addr6_1.m_1);
    sa1 = std::move(sa2);
    EXPECT_EQ(0, memcmp(&sa2.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    sa1 = ip_address(addr6_1.m_1);
    sa2 = std::move(sa1);
    EXPECT_EQ(0, memcmp(&sa2.get_in4_addr(), &addr6_1, sizeof(addr6_1)));
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr6_1, sizeof(addr6_1)));
}

TEST_F(ip_address_test, ip_address_strings)
{
    ip_address sa1_4(m_addr4.m_1);
    ip_address sa1_6(m_addr6.m_1);

    EXPECT_TRUE(sa1_4.to_str() == "153.153.170.170");
    EXPECT_TRUE(sa1_4.to_str(AF_INET) == "153.153.170.170");
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[9999:9999:eeee:eeee:eeee:eeee:9999:9999]");

    ip_v6 addr6;
    addr6.m_2[0] = 0xBBFF000000000000;
    addr6.m_2[1] = 0x0;
    sa1_6 = ip_address(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[0:0:0:ffbb::]");
    addr6.m_2[0] = 0x0;
    addr6.m_2[1] = 0x0;
    sa1_6 = ip_address(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[::]");
    addr6.m_2[0] = 0x0;
    addr6.m_2[1] = 0x9999AAAAFFFF0000;
    sa1_6 = ip_address(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[::ffff:170.170.153.153]");
}
