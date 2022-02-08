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

#ifndef ROUTE_TABLE_MGR_H
#define ROUTE_TABLE_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include <unordered_map>
#include "vma/infra/cache_subject_observer.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "rule_table_mgr.h"
#include "route_entry.h"

typedef std::unordered_map<in_addr_t, route_entry *> in_addr_route_entry_map_t;

struct route_result {
    in_addr_t p_src;
    in_addr_t p_gw;
    uint32_t mtu;
    route_result()
        : p_src(0)
        , p_gw(0)
        , mtu(0)
    {
    }
};

class route_table_mgr : public netlink_socket_mgr<route_val>,
                        public cache_table_mgr<route_rule_table_key, route_val *>,
                        public observer {
public:
    route_table_mgr();
    virtual ~route_table_mgr();

    bool route_resolve(IN route_rule_table_key key, OUT route_result &res);

    route_entry *create_new_entry(route_rule_table_key key, const observer *obs);
    void update_entry(INOUT route_entry *p_ent, bool b_register_to_net_dev = false);

    virtual void notify_cb(event *ev);

protected:
    virtual bool parse_enrty(nlmsghdr *nl_header, route_val *p_val);

private:
    bool find_route_val(const in_addr_t &dst_addr, uint32_t table_id, route_val *&p_val);

    // save current main rt table
    void update_tbl();
    void parse_attr(struct rtattr *rt_attribute, route_val *p_val);

    void rt_mgr_update_source_ip();

    void new_route_event(route_val *netlink_route_val);

    // Holds route_entry for each netdev, to receive events in case there are no other route_entries
    in_addr_route_entry_map_t m_rte_list_for_each_net_dev;
};

extern route_table_mgr *g_p_route_table_mgr;

#endif /* ROUTE_TABLE_MGR_H */
