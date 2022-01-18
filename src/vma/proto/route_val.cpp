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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "vma/util/if.h"

#include "route_val.h"
#include "route_table_mgr.h"
#include "vma/dev/net_device_table_mgr.h"

#define MODULE_NAME "rtv"

#define rt_val_loginfo __log_info_info
#define rt_val_logdbg  __log_info_dbg
#define rt_val_logfunc __log_info_func

#define snprintf_append(buf, ...)                                                                  \
    snprintf((buf) + strlen(buf), sizeof(buf) - strlen(buf), __VA_ARGS__)

static void addr_to_str(int af, const void *src, char *dst, socklen_t size)
{
    const char *r = inet_ntop(af, src, dst, size);
    if (r == NULL && size > 0) {
        *dst = '\0';
    }
}

route_val::route_val()
{
    m_dst_pref_len = 0;
    memset(&m_dst_addr, 0, sizeof(m_dst_addr));
    memset(&m_src_addr, 0, sizeof(m_src_addr));
    memset(&m_gw_addr, 0, sizeof(m_gw_addr));
    m_family = 0;
    m_protocol = 0;
    m_scope = 0;
    m_type = 0;
    m_table_id = 0;
    memset(m_if_name, 0, IFNAMSIZ * sizeof(char));
    m_if_index = 0;
    m_is_valid = false;
    m_b_deleted = false;
    m_b_if_up = true;
    m_mtu = 0;
    memset(m_str, 0, BUFF_SIZE * sizeof(char));
}

void route_val::set_str()
{
    // TODO: improve/streamline conversion to string

    char str_addr[INET6_ADDRSTRLEN + 4] = {};
    const int addr_width = (m_family == AF_INET) ? 15 : 45;
    const int prefix_width = (m_family == AF_INET) ? 2 : 3;

    m_str[0] = '\0';

    snprintf_append(m_str, "dst: ");
    if (!IN6_IS_ADDR_UNSPECIFIED(&m_dst_addr.v6)) {
        addr_to_str(m_family, &m_dst_addr, str_addr, sizeof(str_addr));
        snprintf_append(str_addr, "/%-*d", prefix_width, m_dst_pref_len);
        snprintf_append(m_str, "%-*s", addr_width + prefix_width + 1, str_addr);
    } else {
        snprintf_append(m_str, "%-*s", addr_width + prefix_width + 1, "default");
    }

    if (!IN6_IS_ADDR_UNSPECIFIED(&m_gw_addr.v6)) {
        addr_to_str(m_family, &m_gw_addr, str_addr, sizeof(str_addr));
        snprintf_append(m_str, " gw: %-*s", addr_width, str_addr);
    }

    snprintf_append(m_str, " dev: %-5s", m_if_name);

    if (!IN6_IS_ADDR_UNSPECIFIED(&m_src_addr.v6)) {
        addr_to_str(m_family, &m_src_addr, str_addr, sizeof(str_addr));
        snprintf_append(m_str, " src: %-*s", addr_width, str_addr);
    } else {
        snprintf_append(m_str, "                     ");
    }

    if (m_table_id != RT_TABLE_MAIN) {
        snprintf_append(m_str, " table: %-10u", m_table_id);
    } else {
        snprintf_append(m_str, " table: %-10s", "main");
    }

    snprintf_append(m_str, " scope %3d type %2d index %2d", m_scope, m_type, m_if_index);

    // add route metrics
    if (m_mtu) {
        snprintf_append(m_str, " mtu %d", m_mtu);
    }
    if (m_b_deleted) {
        snprintf_append(m_str, " ---> DELETED");
    }
}

void route_val::print_val()
{
    set_str();
    rt_val_logdbg("%s", to_str());
}

void route_val::set_mtu(uint32_t mtu)
{
    if (mtu > g_p_net_device_table_mgr->get_max_mtu()) {
        rt_val_logdbg("route mtu cannot be bigger then max mtu set on devices");
    } else {
        m_mtu = mtu;
    }
}

const char *route_val::get_dst_addr_str()
{
    thread_local char buf[INET6_ADDRSTRLEN];
    addr_to_str(m_family, &m_dst_addr, buf, sizeof(buf));
    return buf;
}

const char *route_val::get_src_addr_str()
{
    thread_local char buf[INET6_ADDRSTRLEN];
    addr_to_str(m_family, &m_src_addr, buf, sizeof(buf));
    return buf;
}

const char *route_val::get_gw_addr_str()
{
    thread_local char buf[INET6_ADDRSTRLEN];
    addr_to_str(m_family, &m_gw_addr, buf, sizeof(buf));
    return buf;
}
