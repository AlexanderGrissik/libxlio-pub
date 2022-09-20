/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef VERBS_EXTRA_H
#define VERBS_EXTRA_H

#include <rdma/rdma_cma.h>
#include <config.h>
#include <infiniband/verbs.h>
#include "core/util/vtypes.h"
#include "core/util/ip_address.h"
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#if defined(DEFINED_DIRECT_VERBS)
#include "core/ib/mlx5/ib_mlx5.h"
#endif /* DEFINED_DIRECT_VERBS */

#ifndef DEFINED_IBV_WC_WITH_VLAN
//#warning probaly you are trying to compile on OFED which doesnt support VLAN for RAW QP.
//#error when you see this then you need to manually open the below comment and to comment the
// current and the previous lines. #define IBV_WC_WITH_VLAN		1 << 3
#endif

// Wrapper for all IBVERBS & RDMA_CM API to normalize the return code and errno value
// With these marco all ibverbs & rdma_cm failures are caugth and errno is updated
// Without this marco ibverbs & rdma_cm returns sometimes with -1 and sometimes with -errno
inline int _errnocheck(int rc)
{
    if (rc < -1) {
        errno = -rc;
    }
    return rc;
}

#define IF_VERBS_FAILURE_EX(__func__, __err__)                                                     \
    {                                                                                              \
        if (_errnocheck(__func__) && (errno != __err__))
#define IF_VERBS_FAILURE(__func__)                                                                 \
    {                                                                                              \
        if (_errnocheck(__func__))
#define ENDIF_VERBS_FAILURE }

#define IF_RDMACM_FAILURE(__func__) IF_VERBS_FAILURE(__func__)
#define ENDIF_RDMACM_FAILURE        ENDIF_VERBS_FAILURE

// See - IB Arch Spec - 11.6.2 COMPLETION RETURN STATUS
const char *priv_ibv_wc_status_str(enum ibv_wc_status status);

// See - IB Arch Spec - 11.6.3 ASYNCHRONOUS EVENTS
const char *priv_ibv_event_desc_str(enum ibv_event_type type);

#define priv_rdma_cm_event_type_str(__rdma_cm_ev_t__) rdma_event_str(__rdma_cm_ev_t__)

int priv_ibv_modify_qp_to_err(struct ibv_qp *qp);
int priv_ibv_modify_qp_from_err_to_init_raw(struct ibv_qp *qp, uint8_t port_num);
int priv_ibv_modify_qp_from_init_to_rts(struct ibv_qp *qp);

// Return 'ibv_qp_state' of the ibv_qp
int priv_ibv_query_qp_state(struct ibv_qp *qp);

// change  ib rate limit
int priv_ibv_modify_qp_ratelimit(struct ibv_qp *qp, struct xlio_rate_limit_t &rate_limit,
                                 uint32_t rl_changes);

// Modify cq moderation
void priv_ibv_modify_cq_moderation(struct ibv_cq *cq, uint32_t period, uint32_t count);

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK 0xFFF /* define vlan range: 1-4095. taken from <linux/if_vlan.h> */
#endif

#define FS_MASK_ON_8  (0xff)
#define FS_MASK_ON_16 (0xffff)
#define FS_MASK_ON_32 (0xffffffff)
#define FS_MASK_ON_64 (0xffffffffffffffff)

#define FLOW_TAG_MASK ((1 << 20) - 1)
int priv_ibv_query_flow_tag_supported(struct ibv_qp *qp, uint8_t port_num, sa_family_t family);
int priv_ibv_query_burst_supported(struct ibv_qp *qp, uint8_t port_num);

/* DEFINED_VERBS_VERSION:
 * 1 - Legacy Verbs API
 * 2 - Experimental Verbs API
 * 3 - Upstream Verbs API
 */
#if defined(DEFINED_VERBS_VERSION) && (DEFINED_VERBS_VERSION == 1 || DEFINED_VERBS_VERSION == 3)

// ibv_query_device / ibv_create_qp
#define xlio_ibv_device_attr_comp_mask(attr) NOT_IN_USE(attr)
typedef struct ibv_device_attr xlio_ibv_device_attr;

#ifdef DEFINED_IBV_DEVICE_ATTR_EX
#define xlio_ibv_create_qp(pd, attr) ibv_create_qp_ex((pd)->context, attr)
typedef struct ibv_qp_init_attr_ex xlio_ibv_qp_init_attr;
#define xlio_ibv_qp_init_attr_comp_mask(_pd, _attr)                                                \
    {                                                                                              \
        (_attr).pd = _pd;                                                                          \
        (_attr).comp_mask |= IBV_QP_INIT_ATTR_PD;                                                  \
    }

#define xlio_ibv_query_device(context, attr) ibv_query_device_ex(context, NULL, attr)
typedef struct ibv_device_attr_ex xlio_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) &device_attr->orig_attr
#else
#define xlio_ibv_create_qp(pd, attr) ibv_create_qp(pd, attr)
typedef struct ibv_qp_init_attr xlio_ibv_qp_init_attr;
#define xlio_ibv_qp_init_attr_comp_mask(_pd, _attr)                                                \
    {                                                                                              \
        NOT_IN_USE(_pd);                                                                           \
        NOT_IN_USE(_attr);                                                                         \
    }

#define xlio_ibv_query_device(context, attr)  ibv_query_device(context, attr)
typedef xlio_ibv_device_attr xlio_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) device_attr
#endif

// ibv_modify_qp
#define xlio_ibv_modify_qp(qp, attr, mask) ibv_modify_qp(qp, attr, mask)
typedef struct ibv_qp_attr xlio_ibv_qp_attr;
// ibv_poll_cq
#define xlio_ibv_poll_cq(cq, num, wc) ibv_poll_cq(cq, num, wc)
typedef struct ibv_wc xlio_ibv_wc;
#define xlio_wc_flags(wc)  (wc).wc_flags
#define xlio_wc_opcode(wc) (wc).opcode
#define XLIO_IBV_WC_RECV  IBV_WC_RECV
// csum offload
#ifdef DEFINED_IBV_DEVICE_RAW_IP_CSUM
#define xlio_is_rx_hw_csum_supported(attr)                                                          \
    ((attr)->device_cap_flags & (IBV_DEVICE_RAW_IP_CSUM | IBV_DEVICE_UD_IP_CSUM))
#define xlio_wc_rx_hw_csum_ok(wc) (xlio_wc_flags(wc) & IBV_WC_IP_CSUM_OK)
#else
#define xlio_is_rx_hw_csum_supported(attr) 0
#define xlio_wc_rx_hw_csum_ok(wc)          (1)
#endif

typedef int xlio_ibv_cq_init_attr;
#define xlio_ibv_create_cq(context, cqe, cq_context, channel, comp_vector, attr)                   \
    ibv_create_cq(context, cqe, cq_context, channel, comp_vector)

// rx hw timestamp
#define XLIO_IBV_WC_WITH_TIMESTAMP 0
#define xlio_wc_timestamp(wc)       0
#define xlio_ibv_cq_init_ts_attr(attr)                                                             \
    {                                                                                              \
        NOT_IN_USE(attr);                                                                          \
    }

#ifdef DEFINED_IBV_CQ_TIMESTAMP
#define XLIO_IBV_DEVICE_ATTR_HCA_CORE_CLOCK 0
#define XLIO_IBV_VALUES_MASK_RAW_CLOCK      IBV_VALUES_MASK_RAW_CLOCK
#define xlio_ibv_query_values(ctx, values)  ibv_query_rt_values_ex(ctx, values)
#define vma_get_ts_val(values)              values.raw_clock.tv_nsec
typedef struct ibv_values_ex vma_ts_values;
#endif

// ibv_post_send
#define XLIO_IBV_SEND_SIGNALED IBV_SEND_SIGNALED
#define XLIO_IBV_SEND_INLINE   IBV_SEND_INLINE
#ifdef DEFINED_IBV_SEND_IP_CSUM
#define XLIO_IBV_SEND_IP_CSUM (IBV_SEND_IP_CSUM)
#else
#define DEFINED_SW_CSUM
#endif
#define xlio_ibv_send_flags        ibv_send_flags
#define vma_send_wr_send_flags(wr) (wr).send_flags
#define XLIO_IBV_WR_SEND           IBV_WR_SEND
#define xlio_ibv_wr_opcode         ibv_wr_opcode
#define vma_send_wr_opcode(wr)     (wr).opcode

#define XLIO_IBV_WR_TSO               (xlio_ibv_wr_opcode) IBV_WR_TSO
#define vma_check_dev_attr_tso(_attr) 1
#define vma_get_tso_caps(_attr)       (((xlio_ibv_device_attr_ex *)(_attr))->tso_caps)
#define xlio_ibv_qp_init_attr_tso(_attr, _max_tso_header)                                          \
    do {                                                                                           \
        _attr.comp_mask |= IBV_QP_INIT_ATTR_MAX_TSO_HEADER;                                        \
        _attr.max_tso_header = _max_tso_header;                                                    \
    } while (0)
typedef struct ibv_tso_caps xlio_ibv_tso_caps;

// Dummy send
#ifdef DEFINED_IBV_WR_NOP
#define vma_is_nop_supported(device_attr) 1
#define XLIO_IBV_WR_NOP                   (xlio_ibv_wr_opcode) MLX5_OPCODE_NOP
#else
#define vma_is_nop_supported(device_attr) 0
#define XLIO_IBV_WR_NOP                                                                            \
    (xlio_ibv_wr_opcode)(0) // Use 0 as "default" opcode when NOP is not defined.
#endif

#define xlio_ibv_post_send(qp, wr, bad_wr) ibv_post_send(qp, wr, bad_wr)
typedef struct ibv_send_wr xlio_ibv_send_wr;
// ibv_reg_mr
#define XLIO_IBV_ACCESS_LOCAL_WRITE IBV_ACCESS_LOCAL_WRITE
#ifdef DEFINED_IBV_ACCESS_ALLOCATE_MR
#define XLIO_IBV_ACCESS_ALLOCATE_MR IBV_ACCESS_ALLOCATE_MR
#endif
// flow steering
#define XLIO_IBV_FLOW_ATTR_NORMAL                IBV_FLOW_ATTR_NORMAL
#define XLIO_IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK
#define XLIO_IBV_FLOW_SPEC_ETH                   IBV_FLOW_SPEC_ETH
#define XLIO_IBV_FLOW_SPEC_IPV4                  IBV_FLOW_SPEC_IPV4
#define XLIO_IBV_FLOW_SPEC_IPV6                  IBV_FLOW_SPEC_IPV6
#define XLIO_IBV_FLOW_SPEC_TCP                   IBV_FLOW_SPEC_TCP
#define XLIO_IBV_FLOW_SPEC_UDP                   IBV_FLOW_SPEC_UDP
#define xlio_ibv_create_flow(qp, flow)           ibv_create_flow(qp, flow)
#define xlio_ibv_destroy_flow(flow_id)           ibv_destroy_flow(flow_id)
typedef struct ibv_flow xlio_ibv_flow;
typedef struct ibv_flow_attr xlio_ibv_flow_attr;
typedef struct ibv_flow_spec_ib xlio_ibv_flow_spec_ib;
typedef struct ibv_flow_spec_eth xlio_ibv_flow_spec_eth;
typedef struct ibv_flow_spec_ipv4 xlio_ibv_flow_spec_ipv4;
typedef struct ibv_flow_spec_ipv6 xlio_ibv_flow_spec_ipv6;
typedef struct ibv_flow_spec_tcp_udp xlio_ibv_flow_spec_tcp_udp;

// Flow tag
#ifdef DEFINED_IBV_FLOW_TAG
#define XLIO_IBV_FLOW_SPEC_ACTION_TAG IBV_FLOW_SPEC_ACTION_TAG
typedef struct ibv_flow_spec_action_tag xlio_ibv_flow_spec_action_tag;
#define xlio_get_flow_tag(cqe) ntohl((uint32_t)(cqe->sop_drop_qpn))
#else
typedef struct ibv_flow_spec_action_tag_dummy {
} xlio_ibv_flow_spec_action_tag;
#define xlio_get_flow_tag(cqe) 0
#endif // DEFINED_IBV_FLOW_TAG

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
typedef struct ibv_modify_cq_attr xlio_ibv_cq_attr;
#define xlio_ibv_modify_cq(cq, cq_attr, mask) ibv_modify_cq(cq, cq_attr)
#define vma_cq_attr_mask(cq_attr)             (cq_attr).attr_mask
#define vma_cq_attr_moderation(cq_attr)       (cq_attr).moderate
#define XLIO_IBV_CQ_MODERATION                IBV_CQ_ATTR_MODERATE
#endif

// Clock info
#ifdef DEFINED_IBV_CLOCK_INFO
typedef struct mlx5dv_clock_info xlio_ibv_clock_info;
#define xlio_ibv_query_clock_info(ctx, clock_info)   mlx5dv_get_clock_info(ctx, clock_info)
#define xlio_ibv_convert_ts_to_ns(clock_info, hw_ts) mlx5dv_ts_to_ns(clock_info, hw_ts)
#endif // DEFINED_IBV_CLOCK_INFO

// ibv_dm
#ifdef DEFINED_IBV_DM
#define xlio_ibv_alloc_dm(ctx, attr) ibv_alloc_dm(ctx, attr)
#define xlio_ibv_free_dm(dm)         ibv_free_dm(dm)
#define xlio_ibv_reg_dm_mr(mr)                                                                     \
    ibv_reg_dm_mr((mr)->pd, (mr)->dm, 0, (mr)->length,                                             \
                  IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_ZERO_BASED)
#define xlio_ibv_memcpy_dm(dm, attr)                                                               \
    ibv_memcpy_to_dm(dm, (attr)->dm_offset, (attr)->host_addr, (attr)->length)
#define xlio_ibv_init_memcpy_dm(attr, src, head, size)                                             \
    {                                                                                              \
        attr.host_addr = src;                                                                      \
        attr.dm_offset = head;                                                                     \
        attr.length = size;                                                                        \
    }
#define xlio_ibv_init_dm_mr(in_mr, ctx_pd, size, allocated_dm)                                     \
    {                                                                                              \
        in_mr.pd = ctx_pd;                                                                         \
        in_mr.length = size;                                                                       \
        in_mr.dm = allocated_dm;                                                                   \
    }
typedef struct ibv_alloc_dm_attr xlio_ibv_alloc_dm_attr;
typedef struct ibv_dm xlio_ibv_dm;
typedef struct {
    void *host_addr;
    uint64_t dm_offset;
    size_t length;
} xlio_ibv_memcpy_dm_attr;
typedef struct {
    struct ibv_pd *pd;
    size_t length;
    xlio_ibv_dm *dm;
} xlio_ibv_reg_mr_in;
#endif

#ifdef DEFINED_IBV_PACKET_PACING_CAPS
#define XLIO_IBV_QP_RATE_LIMIT             IBV_QP_RATE_LIMIT
#define vma_is_pacing_caps_supported(attr) (attr->packet_pacing_caps.qp_rate_limit_min)

#ifdef DEFINED_IBV_QP_SUPPORT_BURST
#define xlio_ibv_init_burst_attr(qp_attr, rate_limit)                                              \
    {                                                                                              \
        qp_attr.max_burst_sz = rate_limit.max_burst_sz;                                            \
        qp_attr.typical_pkt_sz = rate_limit.typical_pkt_sz;                                        \
    }
typedef struct ibv_qp_rate_limit_attr xlio_ibv_rate_limit_attr;
#define xlio_ibv_modify_qp_rate_limit(qp, attr, mask) ibv_modify_qp_rate_limit(qp, attr)
#define xlio_ibv_init_qps_attr(qp_attr)                                                            \
    {                                                                                              \
        NOT_IN_USE(qp_attr);                                                                       \
    }
#else
typedef xlio_ibv_qp_attr xlio_ibv_rate_limit_attr;
#define xlio_ibv_modify_qp_rate_limit(qp, attr, mask) xlio_ibv_modify_qp(qp, attr, mask)
#define xlio_ibv_init_qps_attr(qp_attr)                                                            \
    {                                                                                              \
        qp_attr.qp_state = IBV_QPS_RTS;                                                            \
    }
#endif // DEFINED_IBV_QP_SUPPORT_BURST

#endif // DEFINED_IBV_PACKET_PACING_CAPS

#endif /* DEFINED_VERBS_VERSION */

// ibv_dm
#ifdef DEFINED_IBV_DM
#define xlio_ibv_dm_size(attr) ((attr)->max_dm_size)
#else
#define xlio_ibv_dm_size(attr) (0)
#endif

#define xlio_ibv_get_device_list(num) ibv_get_device_list(num)

typedef enum {
    RL_RATE = 1 << 0,
    RL_BURST_SIZE = 1 << 1,
    RL_PKT_SIZE = 1 << 2,
} vma_rl_changed;

int vma_rdma_lib_reset();

static inline void ibv_flow_spec_eth_set(xlio_ibv_flow_spec_eth *eth, uint8_t *dst_mac,
                                         uint16_t vlan_tag, bool is_ipv4)
{
    eth->type = XLIO_IBV_FLOW_SPEC_ETH;
    eth->size = sizeof(xlio_ibv_flow_spec_eth);
    eth->val.ether_type = ntohs(is_ipv4 ? ETH_P_IP : ETH_P_IPV6);
    eth->mask.ether_type = FS_MASK_ON_16;
    memcpy(eth->val.dst_mac, dst_mac, ETH_ALEN);
    memset(eth->mask.dst_mac, FS_MASK_ON_8, ETH_ALEN);
    eth->val.vlan_tag = vlan_tag & htons(VLAN_VID_MASK);
    eth->mask.vlan_tag =
        eth->val.vlan_tag ? htons(VLAN_VID_MASK) : 0; // we do not support vlan options
}

template <typename T>
static inline void ibv_flow_spec_set_single_ip(T &spec_ip_val, T &spec_ip_mask,
                                               const ip_address &src_ip)
{
}

typedef decltype(ibv_flow_ipv4_filter::src_ip) spec_ipv4_type;
template <>
inline void ibv_flow_spec_set_single_ip(spec_ipv4_type &spec_ip_val, spec_ipv4_type &spec_ip_mask,
                                        const ip_address &in_ip)
{
    memcpy(&spec_ip_val, &in_ip.get_in4_addr(), sizeof(spec_ipv4_type));
    spec_ip_mask = (!in_ip.is_anyaddr() ? FS_MASK_ON_32 : 0U);
}

typedef decltype(ibv_flow_ipv6_filter::src_ip) spec_ipv6_type;
template <>
inline void ibv_flow_spec_set_single_ip(spec_ipv6_type &spec_ip_val, spec_ipv6_type &spec_ip_mask,
                                        const ip_address &in_ip)
{
    memcpy(&spec_ip_val, &in_ip.get_in6_addr(), sizeof(spec_ipv6_type));
    memset(&spec_ip_mask, in_ip.is_anyaddr() ? 0 : 0xff, sizeof(spec_ipv6_type));
}

static inline void ibv_flow_spec_ip_set(xlio_ibv_flow_spec_ipv4 *ipv4, const ip_address &dst_ip,
                                        const ip_address &src_ip)
{
    ipv4->type = XLIO_IBV_FLOW_SPEC_IPV4;
    ipv4->size = sizeof(xlio_ibv_flow_spec_ipv4);
    ibv_flow_spec_set_single_ip(ipv4->val.src_ip, ipv4->mask.src_ip, src_ip);
    ibv_flow_spec_set_single_ip(ipv4->val.dst_ip, ipv4->mask.dst_ip, dst_ip);
}

static inline void ibv_flow_spec_ip_set(xlio_ibv_flow_spec_ipv6 *ipv6, const ip_address &dst_ip,
                                        const ip_address &src_ip)
{
    ipv6->type = XLIO_IBV_FLOW_SPEC_IPV6;
    ipv6->size = sizeof(xlio_ibv_flow_spec_ipv6);
    ibv_flow_spec_set_single_ip(ipv6->val.src_ip, ipv6->mask.src_ip, src_ip);
    ibv_flow_spec_set_single_ip(ipv6->val.dst_ip, ipv6->mask.dst_ip, dst_ip);
    ipv6->val.flow_label = ipv6->mask.flow_label = 0U;
    ipv6->val.next_hdr = ipv6->mask.next_hdr = 0U;
    ipv6->val.traffic_class = ipv6->mask.traffic_class = 0U;
    ipv6->val.hop_limit = ipv6->mask.hop_limit = 0U;
}

static inline void ibv_flow_spec_tcp_udp_set(xlio_ibv_flow_spec_tcp_udp *tcp_udp, bool is_tcp,
                                             uint16_t dst_port, uint16_t src_port)
{
    tcp_udp->type = is_tcp ? XLIO_IBV_FLOW_SPEC_TCP : XLIO_IBV_FLOW_SPEC_UDP;
    tcp_udp->size = sizeof(xlio_ibv_flow_spec_tcp_udp);
    tcp_udp->val.src_port = src_port;
    if (tcp_udp->val.src_port) {
        tcp_udp->mask.src_port = FS_MASK_ON_16;
    }
    tcp_udp->val.dst_port = dst_port;
    if (tcp_udp->val.dst_port) {
        tcp_udp->mask.dst_port = FS_MASK_ON_16;
    }
}

static inline void ibv_flow_spec_flow_tag_set(xlio_ibv_flow_spec_action_tag *flow_tag,
                                              uint32_t tag_id)
{
    NOT_IN_USE(tag_id);
    if (flow_tag == NULL) {
        return;
    }
#ifdef DEFINED_IBV_FLOW_TAG
    flow_tag->type = XLIO_IBV_FLOW_SPEC_ACTION_TAG;
    flow_tag->size = sizeof(xlio_ibv_flow_spec_action_tag);
    flow_tag->tag_id = tag_id;
#endif // DEFINED_IBV_FLOW_TAG
}

#endif
