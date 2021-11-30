/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef RING_SIMPLE_H
#define RING_SIMPLE_H

#include "ring_slave.h"

#include "vma/dev/gro_mgr.h"
#include "vma/dev/qp_mgr.h"
#include "vma/dev/net_device_table_mgr.h"

struct cq_moderation_info {
    uint32_t period;
    uint32_t count;
    uint64_t packets;
    uint64_t bytes;
    uint64_t prev_packets;
    uint64_t prev_bytes;
    uint32_t missed_rounds;
};

typedef hash_map<void *, uint32_t> user_lkey_map_t;

/**
 * @class ring simple
 *
 * Object to manages the QP and CQ operation
 * This object is used for Rx & Tx at the same time
 *
 */
class ring_simple : public ring_slave {
public:
    ring_simple(int if_index, ring *parent, ring_type_t type);
    virtual ~ring_simple();

    virtual int request_notification(cq_type_t cq_type, uint64_t poll_sn);
    virtual int poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array = NULL);
    virtual int poll_and_process_element_tx(uint64_t *p_cq_poll_sn);
    virtual void adapt_cq_moderation();
    virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
    virtual bool reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst);
    bool reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst); // No locks
    virtual int reclaim_recv_single_buffer(mem_buf_desc_t *rx_reuse); // No locks
    virtual void mem_buf_rx_release(mem_buf_desc_t *p_mem_buf_desc);
    virtual int socketxtreme_poll(struct xlio_socketxtreme_completion_t *vma_completions,
                                  unsigned int ncompletions, int flags);
    virtual int drain_and_proccess();
    virtual int wait_for_notification_and_process_element(int cq_channel_fd, uint64_t *p_cq_poll_sn,
                                                          void *pv_fd_ready_array = NULL);
    // Tx completion handling at the qp_mgr level is just re listing the desc+data buffer in the
    // free lists
    void mem_buf_desc_completion_with_error_tx(
        mem_buf_desc_t *p_tx_wc_buf_desc); // Assume locked...
    void mem_buf_desc_return_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc);
    void mem_buf_desc_return_to_owner_rx(mem_buf_desc_t *p_mem_buf_desc,
                                         void *pv_fd_ready_array = NULL);
    inline int send_buffer(vma_ibv_send_wr *p_send_wqe, vma_wr_tx_packet_attr attr, xlio_tis *tis);
    virtual bool is_up();
    void start_active_qp_mgr();
    void stop_active_qp_mgr();
    virtual mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, bool b_block, pbuf_type type,
                                           int n_num_mem_bufs = 1);
    virtual int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool b_accounting,
                                   bool trylock = false);
    virtual void send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr *p_send_wqe,
                                  vma_wr_tx_packet_attr attr);
    virtual int send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr *p_send_wqe,
                                 vma_wr_tx_packet_attr attr, xlio_tis *tis);
    virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc);
    virtual bool get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr *p_send_wqe);
    inline void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec *systime)
    {
        m_p_ib_ctx->convert_hw_time_to_system_time(hwtime, systime);
    }
    inline uint32_t get_qpn() const
    {
        return (m_p_l2_addr ? ((IPoIB_addr *)m_p_l2_addr)->get_qpn() : 0);
    }
    virtual uint32_t get_underly_qpn() { return m_p_qp_mgr->get_underly_qpn(); }
    virtual int modify_ratelimit(struct xlio_rate_limit_t &rate_limit);
    virtual int get_tx_channel_fd() const
    {
        return m_p_tx_comp_event_channel ? m_p_tx_comp_event_channel->fd : -1;
    };
    virtual uint32_t get_tx_user_lkey(void *addr, size_t length, void *p_mapping = NULL);
    virtual uint32_t get_max_inline_data();
    ib_ctx_handler *get_ctx(ring_user_id_t id)
    {
        NOT_IN_USE(id);
        return m_p_ib_ctx;
    }
#ifdef DEFINED_TSO
    virtual uint32_t get_max_send_sge(void);
    virtual uint32_t get_max_payload_sz(void);
    virtual uint16_t get_max_header_sz(void);
    virtual uint32_t get_tx_lkey(ring_user_id_t id)
    {
        NOT_IN_USE(id);
        return m_tx_lkey;
    }
    virtual bool is_tso(void);
#endif /* DEFINED_TSO */

    struct ibv_comp_channel *get_tx_comp_event_channel() { return m_p_tx_comp_event_channel; }
    void modify_cq_moderation(uint32_t period, uint32_t count);

#ifdef DEFINED_UTLS
    bool tls_tx_supported(void) { return m_tls.tls_tx; }
    bool tls_rx_supported(void) { return m_tls.tls_rx; }
    xlio_tis *tls_context_setup_tx(const xlio_tls_info *info)
    {
        auto_unlocker lock(m_lock_ring_tx);

        xlio_tis *tis = m_p_qp_mgr->tls_context_setup_tx(info);
        if (likely(tis != NULL)) {
            ++m_p_ring_stat->n_tx_tls_contexts;
        }

        /* Do polling to speedup handling of the completion. */
        int ret;
        do {
            uint64_t cq_poll_sn = 0;
            ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&cq_poll_sn);
        } while (ret == 1);

        return tis;
    }
    xlio_tir *tls_create_tir(bool cached)
    {
        /*
         * This method can be called for either RX or TX ring.
         * Locking is required for TX ring with cached=true.
         */
        auto_unlocker lock(m_lock_ring_tx);
        return m_p_qp_mgr->tls_create_tir(cached);
    }
    int tls_context_setup_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t next_record_tcp_sn,
                             xlio_comp_cb_t callback, void *callback_arg)
    {
        /* Protect with TX lock since we post WQEs to the send queue. */
        auto_unlocker lock(m_lock_ring_tx);

        int rc =
            m_p_qp_mgr->tls_context_setup_rx(tir, info, next_record_tcp_sn, callback, callback_arg);
        if (likely(rc == 0)) {
            ++m_p_ring_stat->n_rx_tls_contexts;
        }

        /* Do polling to speedup handling of the completion. */
        int ret;
        do {
            uint64_t cq_poll_sn = 0;
            ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&cq_poll_sn);
        } while (ret == 1);

        return rc;
    }
    void tls_context_resync_tx(const xlio_tls_info *info, xlio_tis *tis, bool skip_static)
    {
        auto_unlocker lock(m_lock_ring_tx);
        m_p_qp_mgr->tls_context_resync_tx(info, tis, skip_static);
    }
    void tls_resync_rx(xlio_tir *tir, const xlio_tls_info *info, uint32_t hw_resync_tcp_sn)
    {
        auto_unlocker lock(m_lock_ring_tx);
        m_p_qp_mgr->tls_resync_rx(tir, info, hw_resync_tcp_sn);
    }
    void tls_get_progress_params_rx(xlio_tir *tir, void *buf, uint32_t lkey)
    {
        auto_unlocker lock(m_lock_ring_tx);
        if (lkey == LKEY_USE_DEFAULT) {
            lkey = m_tx_lkey;
        }
        m_p_qp_mgr->tls_get_progress_params_rx(tir, buf, lkey);
        /* Do polling to speedup handling of the completion. */
        int ret;
        do {
            uint64_t cq_poll_sn = 0;
            ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&cq_poll_sn);
        } while (ret == 1);
    }
    void tls_release_tis(xlio_tis *tis)
    {
        auto_unlocker lock(m_lock_ring_tx);
        m_p_qp_mgr->tls_release_tis(tis);
    }
    void tls_release_tir(xlio_tir *tir)
    {
        /* TIR objects are protected with TX lock */
        auto_unlocker lock(m_lock_ring_tx);
        m_p_qp_mgr->tls_release_tir(tir);
    }
    void tls_tx_post_dump_wqe(xlio_tis *tis, void *addr, uint32_t len, uint32_t lkey, bool first)
    {
        auto_unlocker lock(m_lock_ring_tx);
        if (lkey == LKEY_USE_DEFAULT) {
            lkey = m_tx_lkey;
        }
        m_p_qp_mgr->tls_tx_post_dump_wqe(tis, addr, len, lkey, first);
    }
#endif /* DEFINED_UTLS */
    void post_nop_fence(void)
    {
        auto_unlocker lock(m_lock_ring_tx);
        m_p_qp_mgr->post_nop_fence();
    }

    friend class cq_mgr;
    friend class cq_mgr_mlx5;
    friend class cq_mgr_mlx5_strq;
    friend class qp_mgr;
    friend class qp_mgr_eth_mlx5;
    friend class qp_mgr_eth_mlx5_dpcp;
    friend class rfs;
    friend class rfs_uc;
    friend class rfs_uc_tcp_gro;
    friend class rfs_mc;
    friend class ring_bond;

protected:
    virtual qp_mgr *create_qp_mgr(struct qp_mgr_desc *desc) = 0;
    void create_resources();
    virtual void init_tx_buffers(uint32_t count);
    virtual void inc_cq_moderation_stats(size_t sz_data);
    void set_tx_num_wr(int32_t num_wr) { m_tx_num_wr = m_tx_num_wr_free = num_wr; }
    uint32_t get_tx_num_wr() { return m_tx_num_wr; }
    uint32_t get_mtu() { return m_mtu; }

    ib_ctx_handler *m_p_ib_ctx;
    qp_mgr *m_p_qp_mgr;
    struct cq_moderation_info m_cq_moderation_info;
    cq_mgr *m_p_cq_mgr_rx;
    cq_mgr *m_p_cq_mgr_tx;
    user_lkey_map_t m_user_lkey_map;

private:
    bool is_socketxtreme(void) { return m_socketxtreme.active; }

    void put_ec(struct ring_ec *ec)
    {
        m_socketxtreme.lock_ec_list.lock();
        list_add_tail(&ec->list, &m_socketxtreme.ec_list);
        m_socketxtreme.lock_ec_list.unlock();
    }

    void del_ec(struct ring_ec *ec)
    {
        m_socketxtreme.lock_ec_list.lock();
        list_del_init(&ec->list);
        ec->clear();
        m_socketxtreme.lock_ec_list.unlock();
    }

    inline ring_ec *get_ec(void)
    {
        struct ring_ec *ec = NULL;

        m_socketxtreme.lock_ec_list.lock();
        if (!list_empty(&m_socketxtreme.ec_list)) {
            ec = list_entry(m_socketxtreme.ec_list.next, struct ring_ec, list);
            list_del_init(&ec->list);
        }
        m_socketxtreme.lock_ec_list.unlock();
        return ec;
    }

    struct xlio_socketxtreme_completion_t *get_comp(void) { return m_socketxtreme.completion; }

    struct {
        /* queue of event completion elements
         * this queue is stored events related different sockinfo (sockets)
         * In current implementation every sockinfo (socket) can have single event
         * in this queue
         */
        struct list_head ec_list;

        /* Thread-safety lock for get/put operations under the queue */
        lock_spin lock_ec_list;

        /* This completion is introduced to process events directly w/o
         * storing them in the queue of event completion elements
         */
        struct xlio_socketxtreme_completion_t *completion;

        /* This flag is enabled in case socketxtreme_poll() call is done */
        bool active;
    } m_socketxtreme;

    inline void send_status_handler(int ret, vma_ibv_send_wr *p_send_wqe);
    inline mem_buf_desc_t *get_tx_buffers(pbuf_type type, uint32_t n_num_mem_bufs);
    inline int put_tx_buffers(mem_buf_desc_t *buff_list);
    inline int put_tx_single_buffer(mem_buf_desc_t *buff);
    inline void return_to_global_pool();
    bool is_available_qp_wr(bool b_block);
    void save_l2_address(const L2_address *p_l2_addr)
    {
        delete_l2_address();
        m_p_l2_addr = p_l2_addr->clone();
    };
    void delete_l2_address()
    {
        if (m_p_l2_addr) {
            delete m_p_l2_addr;
        }
        m_p_l2_addr = NULL;
    };

    lock_mutex m_lock_ring_tx_buf_wait;
    uint32_t m_tx_num_bufs;
    uint32_t m_zc_num_bufs;
    uint32_t m_tx_num_wr;
    int32_t m_tx_num_wr_free;
    bool m_b_qp_tx_first_flushed_completion_handled;
    uint32_t m_missing_buf_ref_count;
    uint32_t m_tx_lkey; // this is the registered memory lkey for a given specific device for the
                        // buffer pool use
    gro_mgr m_gro_mgr;
    bool m_up;
    struct ibv_comp_channel *m_p_rx_comp_event_channel;
    struct ibv_comp_channel *m_p_tx_comp_event_channel;
    L2_address *m_p_l2_addr;
    uint32_t m_mtu;

#ifdef DEFINED_TSO
    struct {
        /* Maximum length of TCP payload for TSO */
        uint32_t max_payload_sz;

        /* Maximum length of header for TSO */
        uint16_t max_header_sz;
    } m_tso;
#endif /* DEFINED_TSO */
#ifdef DEFINED_UTLS
    struct {
        /* TLS TX offload is supported */
        bool tls_tx;
        /* TLS RX offload is supported */
        bool tls_rx;
    } m_tls;
#endif /* DEFINED_UTLS */
    struct {
        /* Indicates LRO support */
        bool cap;

        /* Indicate LRO support for segments with PSH flag */
        bool psh_flag;

        /* Indicate LRO support for segments with TCP timestamp option */
        bool time_stamp;

        /* The maximum message size mode
         * 0x0 - TCP header + TCP payload
         * 0x1 - L2 + L3 + TCP header + TCP payload
         */
        uint8_t max_msg_sz_mode;

        /* The minimal size of TCP segment required for coalescing */
        uint16_t min_mss_size;

        /* Array of supported LRO timer periods in microseconds. */
        uint8_t timer_supported_periods[4];

        /* Maximum length of TCP payload for LRO
         * It is calculated from max_msg_sz_mode and safe_mce_sys().rx_buf_size
         */
        uint32_t max_payload_sz;
    } m_lro;
};

class ring_eth : public ring_simple {
public:
    ring_eth(int if_index, ring *parent = NULL, ring_type_t type = RING_ETH,
             bool call_create_res = true)
        : ring_simple(if_index, parent, type)
    {
        net_device_val_eth *p_ndev = dynamic_cast<net_device_val_eth *>(
            g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index()));
        if (p_ndev) {
            m_partition = p_ndev->get_vlan();

            /* Do resource initialization for
             * ring_eth_direct, ring_eth_cb inside related
             * constructors because
             * they use own create_qp_mgr() methods
             */
            if (call_create_res) {
                create_resources();
            }
        }
    }

protected:
    virtual qp_mgr *create_qp_mgr(struct qp_mgr_desc *desc);
};

class ring_ib : public ring_simple {
public:
    ring_ib(int if_index, ring *parent = NULL)
        : ring_simple(if_index, parent, RING_IB)
    {
        net_device_val_ib *p_ndev = dynamic_cast<net_device_val_ib *>(
            g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index()));
        if (p_ndev) {
            m_partition = p_ndev->get_pkey();
            create_resources();
        }
    }

protected:
    virtual qp_mgr *create_qp_mgr(struct qp_mgr_desc *desc);
};

#endif // RING_SIMPLE_H
