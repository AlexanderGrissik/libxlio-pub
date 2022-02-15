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

#include "vma/sock/sock-redirect.h"
#include "vma/util/utils.h"
#include "vlogger/vlogger.h"
#include "utils/bullseye.h"
#include "netlink_socket_mgr.h"

#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h> // getpid()

#ifndef MODULE_NAME
#define MODULE_NAME "netlink_socket_mgr:"
#endif

#define MSG_BUFF_SIZE  81920

netlink_socket_mgr::netlink_socket_mgr()
{
    __log_dbg("");

    m_pid = getpid();
    m_seq_num = 0;

    m_msg_buf = (char *)calloc(MSG_BUFF_SIZE, 1);
    if (m_msg_buf == NULL) {
        __log_err("NL message buffer allocation failed");
        return;
    }

    // Create Socket
    BULLSEYE_EXCLUDE_BLOCK_START
    if ((m_fd = orig_os_api.socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        __log_err("NL socket creation failed, errno = %d", errno);
        return;
    }

    if (orig_os_api.fcntl(m_fd, F_SETFD, FD_CLOEXEC) != 0) {
        __log_warn("Fail in fctl, errno = %d", errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    __log_dbg("Done");
}

netlink_socket_mgr::~netlink_socket_mgr()
{
    __log_dbg("");
    if (m_fd >= 0) {
        orig_os_api.close(m_fd);
        m_fd = -1;
    }
    free(m_msg_buf);

    __log_dbg("Done");
}

// This function build Netlink request to retrieve data (Rule, Route) from kernel.
// Parameters :
//		data_type	: either RULE_DATA_TYPE or ROUTE_DATA_TYPE
//		family	: address family for the request
//		nl_msg	: request to be returned
void netlink_socket_mgr::build_request(nl_data_t data_type, sa_family_t family, struct nlmsghdr **nl_msg)
{
    struct rtmsg *rt_msg;

    assert(MSG_BUFF_SIZE >= NLMSG_SPACE(sizeof(struct rtmsg)));
    memset(m_msg_buf, 0, NLMSG_SPACE(sizeof(struct rtmsg)));

    // point the header and the msg structure pointers into the buffer
    *nl_msg = (struct nlmsghdr *)m_msg_buf;
    rt_msg = (struct rtmsg *)NLMSG_DATA(*nl_msg);

    // Fill in the nlmsg header
    (*nl_msg)->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    (*nl_msg)->nlmsg_seq = ++m_seq_num;
    (*nl_msg)->nlmsg_pid = m_pid;
    (*nl_msg)->nlmsg_type = data_type == RULE_DATA_TYPE ? RTM_GETRULE : RTM_GETROUTE;
    (*nl_msg)->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

    rt_msg->rtm_family = family;
}

// Query built request and receive requested data (Rule, Route)
// Parameters:
//		nl_msg	: request that is built previously.
//		len		: length of received data.
bool netlink_socket_mgr::query(struct nlmsghdr *&nl_msg, int &len)
{
    if (m_fd < 0) {
        return false;
    }

    BULLSEYE_EXCLUDE_BLOCK_START
    if (orig_os_api.send(m_fd, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
        __log_err("Write To Socket Failed...\n");
        return false;
    }
    if ((len = recv_info()) < 0) {
        __log_err("Read From Socket Failed...\n");
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return true;
}

// Receive requested data and save it locally.
// Return length of received data.
int netlink_socket_mgr::recv_info()
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    char *buf_ptr = m_msg_buf;

    do {
        // Receive response from the kernel
        BULLSEYE_EXCLUDE_BLOCK_START
        if ((readLen = orig_os_api.recv(m_fd, buf_ptr, MSG_BUFF_SIZE - msgLen, 0)) < 0) {
            __log_err("NL socket read failed, errno = %d", errno);
            return -1;
        }

        nlHdr = (struct nlmsghdr *)buf_ptr;

        // Check if the header is valid
        if ((NLMSG_OK(nlHdr, (u_int)readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            __log_err("Error in received packet, readLen = %d, msgLen = %d, type=%d, bufLen = %d",
                      readLen, nlHdr->nlmsg_len, nlHdr->nlmsg_type, MSG_BUFF_SIZE);
            if (nlHdr->nlmsg_len == MSG_BUFF_SIZE) {
                __log_err("The buffer we pass to netlink is too small for reading the whole table");
            }
            return -1;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        buf_ptr += readLen;
        msgLen += readLen;

        // Check if the its the last message
        if (nlHdr->nlmsg_type == NLMSG_DONE || (nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            break;
        }

    } while ((nlHdr->nlmsg_seq != m_seq_num) || (nlHdr->nlmsg_pid != m_pid));
    return msgLen;
}

// Update data in a table
void netlink_socket_mgr::update_tbl(nl_data_t data_type)
{
    struct nlmsghdr *nl_msg = NULL;
    int len = 0;

    build_request(data_type, AF_UNSPEC, &nl_msg);
    if (!query(nl_msg, len)) {
        return;
    }
    parse_tbl(len);
}

// Parse received data in a table
// Parameters:
//		len				: length of received data.
//		p_ent_num		: number of rows in received data.
void netlink_socket_mgr::parse_tbl(int len)
{
    struct nlmsghdr *nl_header;

    nl_header = (struct nlmsghdr *)m_msg_buf;
    for (; NLMSG_OK(nl_header, (u_int)len); nl_header = NLMSG_NEXT(nl_header, len)) {
        parse_entry(nl_header);
    }
}

#undef MODULE_NAME
