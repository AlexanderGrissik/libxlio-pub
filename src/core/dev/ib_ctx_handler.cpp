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

#include "vlogger/vlogger.h"
#include "dev/ib_ctx_handler.h"
#include <cinttypes>

#define MODULE_NAME "ibch"
DOCA_LOG_REGISTER(ibch);

#define ibch_logpanic   __log_panic
#define ibch_logerr     __log_err
#define ibch_logwarn    __log_warn
#define ibch_loginfo    __log_info
#define ibch_logdbg     __log_info_dbg
#define ibch_logfunc    __log_info_func
#define ibch_logfuncall __log_info_funcall

ib_ctx_handler::ib_ctx_handler(const char *ibname)
    : m_ibname(ibname)
{
    memset(&m_tso, 0, sizeof(m_tso));
}

ib_ctx_handler::~ib_ctx_handler()
{
#ifndef DEFINED_DPCP_PATH_RX_AND_TX
    delete m_ctx_doca_dev;
#endif // !DEFINED_DPCP_PATH_RX_AND_TX

#ifdef DEFINED_DPCP_PATH_RX_OR_TX
    delete m_ctx_ibv_dev;
#endif // !DEFINED_DPCP_PATH_RX_AND_TX
}

void ib_ctx_handler::set_tso_caps(uint32_t max_payload_sz, uint16_t max_header_sz)
{
    m_tso.max_tso_header_sz = max_header_sz;
    m_tso.max_tso_payload_sz = max_payload_sz;

    if (m_tso.is_tso() && max_header_sz < TSO_DEFAULT_MAX_HEADER_SIZE) {
        ibch_logwarn("HW (%s) supported TSO header size (%" PRIu16
                     ") is less than minimum required (%" PRIu16
                     "). TSO will not be used for this device.",
                     m_ibname.c_str(), max_header_sz, TSO_DEFAULT_MAX_HEADER_SIZE);
    }

    if (m_tso.is_tso() && max_payload_sz > MCE_DEFAULT_MAX_TSO_SIZE) {
        ibch_logwarn("max_tso cap (=%" PRIu32 ") is higher than default TSO size (=%" PRIu32 "). "
                     "Increase XLIO_MAX_TSO_SIZE to get full TSO potential.",
                     max_payload_sz, MCE_DEFAULT_MAX_TSO_SIZE);
    }

    ibch_logdbg("Device %s TSO attributes: is_tso = %d, max_tso_payload_sz = %" PRIu32
                ", max_tso_header_sz = %" PRIu16,
                m_ibname.c_str(), static_cast<int>(m_tso.is_tso()), m_tso.max_tso_payload_sz,
                m_tso.max_tso_header_sz);
}

bool ib_ctx_handler::get_burst_capability() const
{
#ifndef DEFINED_DPCP_PATH_TXs
    return false;
#else // DEFINED_DPCP_PATH_TX
    return get_ctx_ibv_dev().get_burst_capability();
#endif // DEFINED_DPCP_PATH_TX
}

bool ib_ctx_handler::is_packet_pacing_supported(uint32_t rate) const
{
#ifndef DEFINED_DPCP_PATH_TX
    NOT_IN_USE(rate);
    return false;
#else // DEFINED_DPCP_PATH_TX
    return get_ctx_ibv_dev().is_packet_pacing_supported(rate);
#endif // DEFINED_DPCP_PATH_TX
}

bool ib_ctx_handler::get_flow_tag_capability() const
{
#ifndef DEFINED_DPCP_PATH_RX
    return true; // No DOCA API available to check for this cap.
#else // DEFINED_DPCP_PATH_RX
    return get_ctx_ibv_dev().get_flow_tag_capability();
#endif // DEFINED_DPCP_PATH_RX
}

void ib_ctx_handler::set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode)
{
#ifndef DEFINED_DPCP_PATH_RX
    return get_ctx_doca_dev().set_ctx_time_converter_status(conversion_mode);
#else // DEFINED_DPCP_PATH_RX
    return get_ctx_ibv_dev().set_ctx_time_converter_status(conversion_mode);
#endif // DEFINED_DPCP_PATH_RX
}

void ib_ctx_handler::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
{
#ifndef DEFINED_DPCP_PATH_RX
    return get_ctx_doca_dev().convert_hw_time_to_system_time(hwtime, systime);
#else // DEFINED_DPCP_PATH_RX
    return get_ctx_ibv_dev().convert_hw_time_to_system_time(hwtime, systime);
#endif // DEFINED_DPCP_PATH_RX
}

void ib_ctx_handler::print_val()
{
    char str_x[512] = {0};
    char temp_str[512];

    temp_str[0] = '\0';

    str_x[0] = '\0';
    sprintf(str_x, " %s:", get_ibname().c_str());
    strcat(temp_str, str_x);

    ibch_logdbg("%s", temp_str);
}
