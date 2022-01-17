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

#ifndef SOCK_ADDR_H
#define SOCK_ADDR_H

#include <stdio.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "vma/util/vtypes.h"
#include "vma/util/ip_address.h"

static inline sa_family_t get_sa_family(const struct sockaddr* addr)
{
    return addr->sa_family;
}

static inline in_port_t get_sa_port(const struct sockaddr* addr)
{
    return (get_sa_family(addr) == AF_INET ? 
        reinterpret_cast<const struct sockaddr_in*>(addr)->sin_port : 
        reinterpret_cast<const struct sockaddr_in6*>(addr)->sin6_port);
}

static inline std::string sockport2str(const struct sockaddr* addr)
{
    return std::to_string(ntohs(get_sa_port(addr)));
}

static inline std::string sockaddr2str(const struct sockaddr* addr, bool port = false) {
    char buffer[INET6_ADDRSTRLEN];
    std::string rc;

    if (get_sa_family(addr) == AF_INET) {
        rc.reserve(32);
        if (inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in*>(addr)->sin_addr,
                buffer, sizeof(buffer)))
            rc = buffer;
    } else {
        rc.reserve(64);
        rc = '[';
        if (inet_ntop(AF_INET6, &reinterpret_cast<const struct sockaddr_in6*>(addr)->sin6_addr,
                buffer, sizeof(buffer)))
            rc += buffer;
        rc += ']';
    }

    if (port) {
        rc += ':' + sockport2str(addr);
    }

    return rc;
}

class sock_addr {
public:
    sock_addr() { clear_sa(); };

    sock_addr(const struct sockaddr *other, socklen_t size) {
        set_sockaddr(other, size);
    }

    sock_addr(const sock_addr &other) {
        *this = other;
    }

    // @param in_addr Should point either to in_addr or in6_addr according the family.
    sock_addr(sa_family_t f, void* ip_addr, in_port_t p) {
        set_ip_port(f, ip_addr, p);
    };

    ~sock_addr() {};

    const struct sockaddr *get_p_sa() const { return &m_sa; }

    void get_sa(struct sockaddr *sa, socklen_t size) const {
        memcpy(sa, &m_sa, std::min<size_t>(get_socklen(), size));
    }

    sa_family_t get_sa_family() const { return m_sa.sa_family; }

    const ip_address& get_ip_addr() const
    {
        return *(get_sa_family() == AF_INET ?
            reinterpret_cast<const ip_address*>(&m_sa_in.sin_addr) :
            reinterpret_cast<const ip_address*>(&m_sa_in6.sin6_addr));
    }

    in_port_t get_in_port() const { return (get_sa_family() == AF_INET ? m_sa_in.sin_port : m_sa_in6.sin6_port); }

    socklen_t get_socklen() const {
        return static_cast<socklen_t>(get_sa_family() == AF_INET ?
            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    }

    bool is_anyaddr() const {
        if (get_sa_family() == AF_INET)
            return m_sa_in.sin_addr.s_addr == INADDR_ANY;

        return (0 == memcmp(&m_sa_in6.sin6_addr, &in6addr_any, sizeof(in6addr_any)));
    };

    bool is_mc() const {
        if (get_sa_family() == AF_INET)
            return IN_MULTICAST_N(m_sa_in.sin_addr.s_addr);

        return false; // [TODO IPV6] Implement for IPv6
    };

    void set_sockaddr(const struct sockaddr *sa, socklen_t size) {
        clear_sa();
        memcpy(&m_sa, sa, std::min<size_t>(get_socklen_max(), size));
    }

    void set_any(sa_family_t f) {
        clear_sa();
        m_sa.sa_family = f;

        if (AF_INET == f) {
            m_sa_in.sin_addr.s_addr = INADDR_ANY;
            m_sa_in.sin_port = INPORT_ANY;
        } else {
            memcpy(&m_sa_in6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
            m_sa_in6.sin6_port = INPORT_ANY;
        }
    }

    void set_ip_port(sa_family_t f, const void* ip_addr, in_port_t p) {
        clear_sa();
        m_sa.sa_family = f;

        if (AF_INET == f) {
            m_sa_in.sin_addr = *reinterpret_cast<const struct in_addr*>(ip_addr);
            m_sa_in.sin_port = p;
        } else {
            m_sa_in6.sin6_addr = *reinterpret_cast<const struct in6_addr*>(ip_addr);
            m_sa_in6.sin6_port = p;
        }
    }

    void set_in_addr(const ip_address& ip) { 
        if (get_sa_family() == AF_INET)
            m_sa_in.sin_addr = reinterpret_cast<const in_addr&>(ip);
        else
            m_sa_in6.sin6_addr = reinterpret_cast<const in6_addr&>(ip);
    }

    sock_addr &operator=(const sock_addr &other) { m_sa_in6 = other.m_sa_in6; return *this; }

    bool operator==(const sock_addr &other) const {
        return (0 == memcmp(&m_sa_in6, &other.m_sa_in6, get_socklen_max()));
    }

    size_t hash(void) const
    {
        uint8_t csum = 0;
        const uint8_t *pval = reinterpret_cast<const uint8_t*>(this);
        socklen_t sockaddr_size = get_socklen();
        for (socklen_t i = 0; i < sockaddr_size; ++i, ++pval) {
            csum ^= *pval;
        }
        return csum;
    }

    std::string to_str_port() const { return sockport2str(&m_sa); }

    std::string to_str_ip_port(bool port = false) const { return sockaddr2str(&m_sa, port); }

private:

    void clear_sa() { memset(&m_sa_in6, 0, get_socklen_max()); }

    size_t get_socklen_max() const { return sizeof(struct sockaddr_in6); };
    
    union {
        struct sockaddr     m_sa;
        struct sockaddr_in  m_sa_in;
        struct sockaddr_in6 m_sa_in6;
    };
};

#endif /*SOCK_ADDR_H*/
