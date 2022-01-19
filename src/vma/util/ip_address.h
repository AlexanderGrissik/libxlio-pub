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

#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H

#include <arpa/inet.h>
#include <string.h>
#include <string>
#include "vma/util/vtypes.h"

// This class must be compatible with sock_addr (see sock_addr.h) and should not contain any member
// except IPv4/IPv6 union. If any other memeber is needed, this class should be split into two
// classes ip_addr and ip_address.
class ip_address {
public:
    ip_address(in_addr_t ip4)
        : m_ip6 {}
    { // [TODO IPV6] Temporary
        m_ip = ip4;
    };

    ip_address(in_addr ip4)
        : m_ip6 {}
    {
        m_ip4 = ip4;
    };

    ip_address(in6_addr ip6)
        : m_ip6(ip6)
    {
    }

    ip_address(const ip_address &addr) { *this = addr; }

    ip_address(ip_address &&addr) { *this = addr; }

    const std::string to_str() const { return to_str(AF_INET); } // [TODO IPV6] Temporary

    const std::string to_str(sa_family_t family) const
    {
        char buffer[INET6_ADDRSTRLEN];
        std::string rc;

        if (family == AF_INET) {
            rc.reserve(32);
            if (inet_ntop(AF_INET, &m_ip4, buffer, sizeof(buffer))) {
                rc = buffer;
            }
        } else {
            rc.reserve(64);
            rc = '[';
            if (inet_ntop(AF_INET6, &m_ip6, buffer, sizeof(buffer))) {
                rc += buffer;
            }
            rc += ']';
        }

        return rc;
    }

    in_addr_t get_in_addr() const { return m_ip; }; // [TODO IPV6] Temporary

    const in_addr &get_in4_addr() const { return m_ip4; };

    const in6_addr &get_in6_addr() const { return m_ip6; };

    bool is_mc() const { return (IN_MULTICAST_N(m_ip)); }; // [TODO IPV6] Implement for IPv6
    bool is_anyaddr() const { return (unlikely(m_ip6_64[0] == 0) && likely(m_ip6_64[1] == 0)); };

    bool operator==(const ip_address &ip) const
    {
        return (m_ip6_64[0] == ip.m_ip6_64[0] && m_ip6_64[1] == ip.m_ip6_64[1]);
    };

    bool operator!=(const ip_address &ip) const
    {
        return (m_ip6_64[0] != ip.m_ip6_64[0] || m_ip6_64[1] != ip.m_ip6_64[1]);
    };

    ip_address &operator=(const ip_address &ip)
    {
        m_ip6 = ip.m_ip6;
        return *this;
    }

    ip_address &operator=(ip_address &&ip)
    {
        m_ip6 = ip.m_ip6;
        return *this;
    }

    friend std::hash<ip_address>;

private:
    union {
        in6_addr m_ip6;
        uint64_t m_ip6_64[2];
        in_addr m_ip4;
        in_addr_t m_ip;
    };
};

namespace std {
template <> class hash<ip_address> {
public:
    size_t operator()(const ip_address &key) const
    {
        hash<uint64_t> _hash;
        return _hash(key.m_ip6_64[0] ^ key.m_ip6_64[1]);
    }
};
} // namespace std

#endif /* IP_ADDRESS_H */
