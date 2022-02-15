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

#ifndef NETLINK_SOCKET_MGR_H
#define NETLINK_SOCKET_MGR_H

#include "vma/util/vtypes.h"

#include <sys/socket.h> // sa_family_t

// Forward declarations
struct nlmsghdr;

// This enum specify the type of data to be retrieve using netlink socket.
enum nl_data_t { RULE_DATA_TYPE, ROUTE_DATA_TYPE };

/*
 * This class manage retrieving data (Rule, Route) from kernel using netlink socket.
 */
class netlink_socket_mgr {
public:
    netlink_socket_mgr();
    virtual ~netlink_socket_mgr();

protected:
    virtual void parse_entry(struct nlmsghdr *nl_header) = 0;
    virtual void update_tbl(nl_data_t data_type);

private:
    void build_request(nl_data_t data_type, sa_family_t family, struct nlmsghdr **nl_msg);
    bool query(struct nlmsghdr *&nl_msg, int &len);
    int recv_info();
    void parse_tbl(int len);

    int m_fd; // netlink socket to communicate with the kernel
    uint32_t m_pid; // process pid
    uint32_t m_seq_num; // seq num of the netlink messages
    char *m_msg_buf; // we use this buffer for sending/receiving netlink messages
};

#endif /* NETLINK_SOCKET_MGR_H */
