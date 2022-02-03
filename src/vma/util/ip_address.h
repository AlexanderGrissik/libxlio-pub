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
// except IPv4/IPv6 union and must now have virtual methods.
// Class ip_addr is an extention to this class (see below) which allows more members and vtable.
class ip_address {
public:
    ip_address(in_addr_t ip4)
        : m_ip6 {}
    {
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

    in_addr_t get_in_addr() const { return m_ip; };

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

protected:
    union {
        in6_addr m_ip6;
        uint64_t m_ip6_64[2];
        in_addr m_ip4;
        in_addr_t m_ip;
    };
};

// This class is an extention to the ip_address class. It allows more members and virtual methods.
// However, new members should be added with caution since this still may be used in hashes and
// performance oriented pathes.
class ip_addr : public ip_address {
public:
    ip_addr(in_addr_t ip4)
        : ip_address(ip4)
        , m_family(AF_INET)
    {
    }

    ip_addr(in_addr ip4)
        : ip_address(ip4)
        , m_family(AF_INET)
    {
    }

    ip_addr(in6_addr ip6)
        : ip_address(ip6)
        , m_family(AF_INET6)
    {
    }

    ip_addr(const ip_address &ip, sa_family_t family)
        : ip_address(ip)
        , m_family(family)
    {
    }

    ip_addr(ip_address &&ip, sa_family_t family)
        : ip_address(ip)
        , m_family(family)
    {
    }

    ip_addr(const ip_addr &addr)
        : ip_address(addr)
        , m_family(addr.m_family)
    {
    }

    ip_addr(ip_addr &addr)
        : ip_address(addr)
        , m_family(addr.m_family)
    {
    }

    sa_family_t get_family() const { return m_family; }

    bool is_ipv4() const { return (m_family == AF_INET); }

    bool is_ipv6() const { return (m_family == AF_INET6); }

    const std::string to_str() const { return ip_address::to_str(m_family); }

    bool operator==(const ip_addr &ip) const
    {
        return (ip_address::operator==(ip) && m_family == ip.m_family);
    };

    bool operator!=(const ip_addr &ip) const
    {
        return (ip_address::operator!=(ip) || m_family != ip.m_family);
    };

    ip_addr &operator=(const ip_addr &ip)
    {
        m_family = ip.m_family;
        ip_address::operator=(ip);
        return *this;
    }

    ip_addr &operator=(ip_addr &&ip) { return *this = ip; }

    friend std::hash<ip_addr>;

private:
    sa_family_t m_family;
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
template <> class hash<ip_addr> {
public:
    size_t operator()(const ip_addr &key) const
    {
        hash<uint64_t> _hash;
        return _hash(key.m_ip6_64[0] ^ key.m_ip6_64[1] ^
                     (static_cast<uint64_t>(key.get_family()) << 30U));
    }
};
} // namespace std

#endif /* IP_ADDRESS_H */
