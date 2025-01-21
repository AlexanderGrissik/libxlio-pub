/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef IB_CTX_HANDLER_H
#define IB_CTX_HANDLER_H

#include "dpcp/ib_ctx_handler_ibv.h"
#include "doca/ib_ctx_handler_doca.h"

// Max-Header = ETH(14) + IP(20) + TCP(20) + TCP OPTIONS(40)
#define TSO_DEFAULT_MAX_HEADER_SIZE static_cast<uint16_t>(94U)

struct dev_tso_caps {
    uint32_t max_tso_payload_sz; // Maximum length of TCP payload for TSO
    uint16_t max_tso_header_sz; // Maximum length of header for TSO
    bool is_tso() const { return (max_tso_payload_sz && max_tso_header_sz); }
};

class ib_ctx_handler {
public:
    ib_ctx_handler(const char *ibname);
    virtual ~ib_ctx_handler();

    const std::string &get_ibname() const { return m_ibname; }
    bool get_flow_tag_capability() const;
    bool get_burst_capability() const;
    bool is_packet_pacing_supported(uint32_t rate) const;
    void print_val();
    void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime);
    void set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode);
    void set_tso_caps(uint32_t max_payload_sz, uint16_t max_header_sz);
    const dev_tso_caps &get_tso_caps() const { return m_tso; }

private:
    std::string m_ibname;
    dev_tso_caps m_tso;

#ifdef DEFINED_DPCP_PATH_RX_OR_TX
public:
    ib_ctx_handler_ibv &get_ctx_ibv_dev() { return *m_ctx_ibv_dev; }
    const ib_ctx_handler_ibv &get_ctx_ibv_dev() const { return *m_ctx_ibv_dev; }
    void construct_ctx_ibv_dev(ibv_device *ibvdevice)
    {
        m_ctx_ibv_dev = new ib_ctx_handler_ibv(ibvdevice, *this);
    }

private:
    ib_ctx_handler_ibv *m_ctx_ibv_dev;
#endif // DEFINED_DPCP_PATH_RX_OR_TX

#ifndef DEFINED_DPCP_PATH_RX_AND_TX
public:
    ib_ctx_handler_doca &get_ctx_doca_dev() { return *m_ctx_doca_dev; }
    void construct_ctx_doca_dev(doca_devinfo *devinfo, const char *ifname)
    {
        m_ctx_doca_dev = new ib_ctx_handler_doca(devinfo, *this, ifname);
    }

private:
    ib_ctx_handler_doca *m_ctx_doca_dev;
#endif
};

#endif
