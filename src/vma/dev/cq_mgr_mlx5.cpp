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

#include "cq_mgr_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <vma/util/valgrind.h>
#include "cq_mgr.inl"
#include "cq_mgr_mlx5.inl"
#include "qp_mgr.h"
#include "qp_mgr_eth_mlx5.h"
#include "ring_simple.h"

#define MODULE_NAME "cqm_mlx5"

#define cq_logfunc    __log_info_func
#define cq_logdbg     __log_info_dbg
#define cq_logerr     __log_info_err
#define cq_logpanic   __log_info_panic
#define cq_logfuncall __log_info_funcall

cq_mgr_mlx5::cq_mgr_mlx5(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, uint32_t cq_size,
                         struct ibv_comp_channel *p_comp_event_channel, bool is_rx,
                         bool call_configure)
    : cq_mgr(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel, is_rx, call_configure)
    , m_qp(NULL)
    , m_rx_hot_buffer(NULL)
    , m_b_sysvar_enable_socketxtreme(safe_mce_sys().enable_socketxtreme)
{
    cq_logfunc("");

    memset(&m_mlx5_cq, 0, sizeof(m_mlx5_cq));
}

uint32_t cq_mgr_mlx5::clean_cq()
{
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;
    mem_buf_desc_t *buff;

    if (m_b_is_rx) {
        /* Sanity check for cq: initialization of tx and rx cq has difference:
         * tx - is done in qp_mgr::configure()
         * rx - is done in qp_mgr::up()
         * as a result rx cq can be created but not initialized
         */
        if (NULL == m_qp) {
            return 0;
        }

        buff_status_e status = BS_OK;
        while ((buff = poll(status))) {
            if (process_cq_element_rx(buff, status)) {
                m_rx_queue.push_back(buff);
            }
            ++ret_total;
        }
        update_global_sn(cq_poll_sn, ret_total);
    } else { // Tx
        int ret = 0;
        /* coverity[stack_use_local_overflow] */
        vma_ibv_wc wce[MCE_MAX_CQ_POLL_BATCH];
        while ((ret = cq_mgr::poll(wce, MCE_MAX_CQ_POLL_BATCH, &cq_poll_sn)) > 0) {
            for (int i = 0; i < ret; i++) {
                buff = process_cq_element_tx(&wce[i]);
                if (buff) {
                    m_rx_queue.push_back(buff);
                }
            }
            ret_total += ret;
        }
    }

    return ret_total;
}

cq_mgr_mlx5::~cq_mgr_mlx5()
{
    cq_logfunc("");
    cq_logdbg("destroying CQ as %s", (m_b_is_rx ? "Rx" : "Tx"));
}

mem_buf_desc_t *cq_mgr_mlx5::poll(enum buff_status_e &status)
{
    mem_buf_desc_t *buff = NULL;

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
    RDTSC_TAKE_END(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL);
#endif // RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL

#if defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) || defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
    RDTSC_TAKE_START_RX_VERBS_POLL(RDTSC_FLOW_RX_VERBS_READY_POLL, RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif // RDTSC_MEASURE_RX_VERBS_READY_POLL || RDTSC_MEASURE_RX_VERBS_IDLE_POLL

    if (unlikely(NULL == m_rx_hot_buffer)) {
        if (likely(m_qp->m_mlx5_qp.rq.tail != (m_qp->m_mlx5_qp.rq.head))) {
            uint32_t index = m_qp->m_mlx5_qp.rq.tail & (m_qp_rec.qp->m_rx_num_wr - 1);
            m_rx_hot_buffer = (mem_buf_desc_t *)m_qp->m_rq_wqe_idx_to_wrid[index];
            m_qp->m_rq_wqe_idx_to_wrid[index] = 0;
            prefetch((void *)m_rx_hot_buffer);
            prefetch((uint8_t *)m_mlx5_cq.cq_buf +
                     ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));
        } else {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
            RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif

#if defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) || defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
            RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL,
                                                           RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM);
#endif // RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL || RDTSC_MEASURE_RX_CQE_RECEIVEFROM
            /* If rq_tail and rq_head are pointing to the same wqe,
             * the wq is empty and there is no cqe to be received */
            return NULL;
        }
    }
    vma_mlx5_cqe *cqe = check_cqe();
    if (likely(cqe)) {
        /* Update the consumer index */
        ++m_mlx5_cq.cq_ci;
        rmb();
        cqe_to_mem_buff_desc(cqe, m_rx_hot_buffer, status);

        ++m_qp->m_mlx5_qp.rq.tail;
        *m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci & 0xffffff);

        buff = m_rx_hot_buffer;
        m_rx_hot_buffer = NULL;

#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
        RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_READY_POLL);
#endif // RDTSC_MEASURE_RX_VERBS_READY_POLL

#ifdef RDTSC_MEASURE_RX_READY_POLL_TO_LWIP
        RDTSC_TAKE_START(RDTSC_FLOW_RX_READY_POLL_TO_LWIP);
#endif
    } else {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
        RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif

#if defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) || defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
        RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL,
                                                       RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM);
#endif // RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL || RDTSC_MEASURE_RX_CQE_RECEIVEFROM

        prefetch((void *)m_rx_hot_buffer);
    }

    prefetch((uint8_t *)m_mlx5_cq.cq_buf +
             ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));

    return buff;
}

void cq_mgr_mlx5::cqe_to_mem_buff_desc(struct vma_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc,
                                       enum buff_status_e &status)
{
    struct mlx5_err_cqe *ecqe;
    ecqe = (struct mlx5_err_cqe *)cqe;

    switch (MLX5_CQE_OPCODE(cqe->op_own)) {
    case MLX5_CQE_RESP_WR_IMM:
        cq_logerr("IBV_WC_RECV_RDMA_WITH_IMM is not supported");
        status = BS_CQE_RESP_WR_IMM_NOT_SUPPORTED;
        break;
    case MLX5_CQE_RESP_SEND:
    case MLX5_CQE_RESP_SEND_IMM:
    case MLX5_CQE_RESP_SEND_INV: {
        status = BS_OK;
        p_rx_wc_buf_desc->sz_data = ntohl(cqe->byte_cnt);
#ifdef DEFINED_UTLS
        p_rx_wc_buf_desc->rx.tls_decrypted = (cqe->pkt_info >> 3) & 0x3;
#endif /* DEFINED_UTLS */
        p_rx_wc_buf_desc->rx.hw_raw_timestamp = ntohll(cqe->timestamp);
        p_rx_wc_buf_desc->rx.flow_tag_id = vma_get_flow_tag(cqe);
        p_rx_wc_buf_desc->rx.is_sw_csum_need =
            !(m_b_is_rx_hw_csum_on && (cqe->hds_ip_ext & MLX5_CQE_L4_OK) &&
              (cqe->hds_ip_ext & MLX5_CQE_L3_OK));
        if (cqe->lro_num_seg > 1) {
            lro_update_hdr(cqe, p_rx_wc_buf_desc);
            m_p_cq_stat->n_rx_lro_packets++;
            m_p_cq_stat->n_rx_lro_bytes += p_rx_wc_buf_desc->sz_data;
        }
        return;
    }
    case MLX5_CQE_INVALID: /* No cqe!*/
    {
        cq_logerr("We should no receive a buffer without a cqe\n");
        status = BS_CQE_INVALID;
        break;
    }
    case MLX5_CQE_REQ:
    case MLX5_CQE_REQ_ERR:
    case MLX5_CQE_RESP_ERR:
    default: {
        if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR == ecqe->syndrome) {
            status = BS_IBV_WC_WR_FLUSH_ERR;
        } else {
            status = BS_GENERAL_ERR;
        }
        /*
          IB compliant completion with error syndrome:
          0x1: Local_Length_Error
          0x2: Local_QP_Operation_Error
          0x4: Local_Protection_Error
          0x5: Work_Request_Flushed_Error
          0x6: Memory_Window_Bind_Error
          0x10: Bad_Response_Error
          0x11: Local_Access_Error
          0x12: Remote_Invalid_Request_Error
          0x13: Remote_Access_Error
          0x14: Remote_Operation_Error
          0x15: Transport_Retry_Counter_Exceeded
          0x16: RNR_Retry_Counter_Exceeded
          0x22: Aborted_Error
          other: Reserved
         */
        break;
    }
    }
}

int cq_mgr_mlx5::drain_and_proccess(uintptr_t *p_recycle_buffers_last_wr_id /*=NULL*/)
{
    cq_logfuncall("cq was %s drained. %d processed wce since last check. %d wce in m_rx_queue",
                  (m_b_was_drained ? "" : "not "), m_n_wce_counter, m_rx_queue.size());

    /* CQ polling loop until max wce limit is reached for this interval or CQ is drained */
    uint32_t ret_total = 0;
    uint64_t cq_poll_sn = 0;

    /* drain_and_proccess() is mainly called in following cases as
     * Internal thread:
     *   Frequency of real polling can be controlled by
     *   VMA_PROGRESS_ENGINE_INTERVAL and VMA_PROGRESS_ENGINE_WCE_MAX.
     * socketxtreme:
     *   User does socketxtreme_poll()
     * Cleanup:
     *   QP down logic to release rx buffers should force polling to do this.
     *   Not null argument indicates one.
     */

    if (m_b_sysvar_enable_socketxtreme) {
        while (((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) && (!m_b_was_drained)) ||
               (p_recycle_buffers_last_wr_id)) {
            int ret = 0;
            vma_mlx5_cqe *cqe_arr[MCE_MAX_CQ_POLL_BATCH];

            for (int i = 0; i < MCE_MAX_CQ_POLL_BATCH; ++i) {
                cqe_arr[i] = get_cqe();
                if (cqe_arr[i]) {
                    ++ret;
                    wmb();
                    *m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci);
                    if (m_b_is_rx) {
                        ++m_qp->m_mlx5_qp.rq.tail;
                    }
                } else {
                    break;
                }
            }

            if (!ret) {
                m_b_was_drained = true;
                return ret_total;
            }

            m_n_wce_counter += ret;
            if (ret < MCE_MAX_CQ_POLL_BATCH) {
                m_b_was_drained = true;
            }

            for (int i = 0; i < ret; i++) {
                uint32_t wqe_sz = 0;
                vma_mlx5_cqe *cqe = cqe_arr[i];
                vma_ibv_wc wce;

                uint16_t wqe_ctr = ntohs(cqe->wqe_counter);
                if (m_b_is_rx) {
                    wqe_sz = m_qp->m_rx_num_wr;
                } else {
                    wqe_sz = m_qp->m_tx_num_wr;
                }

                int index = wqe_ctr & (wqe_sz - 1);

                /* We need to processes rx data in case
                 * wce.status == IBV_WC_SUCCESS
                 * and release buffers to rx pool
                 * in case failure
                 */
                m_rx_hot_buffer = (mem_buf_desc_t *)(uintptr_t)m_qp->m_rq_wqe_idx_to_wrid[index];
                memset(&wce, 0, sizeof(wce));
                wce.wr_id = (uintptr_t)m_rx_hot_buffer;
                cqe_to_vma_wc(cqe, &wce);

                m_rx_hot_buffer = cq_mgr::process_cq_element_rx(&wce);
                if (m_rx_hot_buffer) {
                    if (p_recycle_buffers_last_wr_id) {
                        m_p_cq_stat->n_rx_pkt_drop++;
                        reclaim_recv_buffer_helper(m_rx_hot_buffer);
                    } else {
                        bool procces_now = false;
                        if (m_transport_type == VMA_TRANSPORT_ETH) {
                            procces_now = is_eth_tcp_frame(m_rx_hot_buffer);
                        }
                        // We process immediately all non udp/ip traffic..
                        if (procces_now) {
                            m_rx_hot_buffer->rx.is_vma_thr = true;
                            if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                                !compensate_qp_poll_success(m_rx_hot_buffer)) {
                                process_recv_buffer(m_rx_hot_buffer, NULL);
                            }
                        } else { // udp/ip traffic we just put in the cq's rx queue
                            m_rx_queue.push_back(m_rx_hot_buffer);
                            mem_buf_desc_t *buff_cur = m_rx_queue.get_and_pop_front();
                            if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                                !compensate_qp_poll_success(buff_cur)) {
                                m_rx_queue.push_front(buff_cur);
                            }
                        }
                    }
                }
                if (p_recycle_buffers_last_wr_id) {
                    *p_recycle_buffers_last_wr_id = (uintptr_t)wce.wr_id;
                }
            }
            ret_total += ret;
        }
    } else {
        while (((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) && (!m_b_was_drained)) ||
               (p_recycle_buffers_last_wr_id)) {
            buff_status_e status = BS_OK;
            mem_buf_desc_t *buff = poll(status);
            if (NULL == buff) {
                update_global_sn(cq_poll_sn, ret_total);
                m_b_was_drained = true;
                m_p_ring->m_gro_mgr.flush_all(NULL);
                return ret_total;
            }

            ++m_n_wce_counter;

            if (process_cq_element_rx(buff, status)) {
                if (p_recycle_buffers_last_wr_id) {
                    m_p_cq_stat->n_rx_pkt_drop++;
                    reclaim_recv_buffer_helper(buff);
                } else {
                    bool procces_now = false;
                    if (m_transport_type == VMA_TRANSPORT_ETH) {
                        procces_now = is_eth_tcp_frame(buff);
                    }
                    /* We process immediately all non udp/ip traffic.. */
                    if (procces_now) {
                        buff->rx.is_vma_thr = true;
                        if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                            !compensate_qp_poll_success(buff)) {
                            process_recv_buffer(buff, NULL);
                        }
                    } else { /* udp/ip traffic we just put in the cq's rx queue */
                        m_rx_queue.push_back(buff);
                        mem_buf_desc_t *buff_cur = m_rx_queue.front();
                        m_rx_queue.pop_front();
                        if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                            !compensate_qp_poll_success(buff_cur)) {
                            m_rx_queue.push_front(buff_cur);
                        }
                    }
                }
            }

            if (p_recycle_buffers_last_wr_id) {
                *p_recycle_buffers_last_wr_id = (uintptr_t)buff;
            }

            ++ret_total;
        }

        update_global_sn(cq_poll_sn, ret_total);

        m_p_ring->m_gro_mgr.flush_all(NULL);
    }

    m_n_wce_counter = 0;
    m_b_was_drained = false;

    // Update cq statistics
    m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
    m_p_cq_stat->n_rx_drained_at_once_max =
        std::max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

    return ret_total;
}

mem_buf_desc_t *cq_mgr_mlx5::process_cq_element_rx(mem_buf_desc_t *p_mem_buf_desc,
                                                   enum buff_status_e status)
{
    /* Assume locked!!! */
    cq_logfuncall("");

    /* we use context to verify that on reclaim rx buffer path we return the buffer to the right CQ
     */
    p_mem_buf_desc->rx.is_vma_thr = false;
    p_mem_buf_desc->rx.context = NULL;
    p_mem_buf_desc->rx.socketxtreme_polled = false;

    if (unlikely(status != BS_OK)) {
        m_p_next_rx_desc_poll = NULL;
        if (p_mem_buf_desc->p_desc_owner) {
            reclaim_recv_buffer_helper(p_mem_buf_desc);
        } else {
            /* AlexR: are we throwing away a data buffer and a mem_buf_desc element? */
            cq_logdbg("no desc_owner(wr_id=%p)", p_mem_buf_desc);
        }

        return NULL;
    }

    if (m_n_sysvar_rx_prefetch_bytes_before_poll) {
        m_p_next_rx_desc_poll = p_mem_buf_desc->p_prev_desc;
        p_mem_buf_desc->p_prev_desc = NULL;
    }

    VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

    prefetch_range((uint8_t *)p_mem_buf_desc->p_buffer + m_sz_transport_header,
                   std::min(p_mem_buf_desc->sz_data - m_sz_transport_header,
                            (size_t)m_n_sysvar_rx_prefetch_bytes));

    return p_mem_buf_desc;
}

int cq_mgr_mlx5::poll_and_process_element_rx(uint64_t *p_cq_poll_sn, void *pv_fd_ready_array)
{
    /* Assume locked!!! */
    cq_logfuncall("");

    uint32_t ret_rx_processed = process_recv_queue(pv_fd_ready_array);
    if (unlikely(ret_rx_processed >= m_n_sysvar_cq_poll_batch_max)) {
        m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
        return ret_rx_processed;
    }

    if (m_p_next_rx_desc_poll) {
        prefetch_range((uint8_t *)m_p_next_rx_desc_poll->p_buffer,
                       m_n_sysvar_rx_prefetch_bytes_before_poll);
    }

    if (m_b_sysvar_enable_socketxtreme) {
        if (unlikely(m_rx_hot_buffer == NULL)) {
            int index = m_qp->m_mlx5_qp.rq.tail & (m_qp->m_rx_num_wr - 1);
            m_rx_hot_buffer = (mem_buf_desc_t *)(uintptr_t)m_qp->m_rq_wqe_idx_to_wrid[index];
            m_rx_hot_buffer->rx.context = NULL;
            m_rx_hot_buffer->rx.is_vma_thr = false;
            m_rx_hot_buffer->rx.socketxtreme_polled = false;
        } else {
            vma_mlx5_cqe *cqe_err = NULL;
            vma_mlx5_cqe *cqe = get_cqe(&cqe_err);

            if (likely(cqe)) {
                buff_status_e status = BS_OK;

                ++m_n_wce_counter;
                ++m_qp->m_mlx5_qp.rq.tail;

                cqe_to_mem_buff_desc(cqe, m_rx_hot_buffer, status);

                if (unlikely(++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv)) {
                    (void)compensate_qp_poll_success(m_rx_hot_buffer);
                }
                process_recv_buffer(m_rx_hot_buffer, pv_fd_ready_array);
                ++ret_rx_processed;
                m_rx_hot_buffer = NULL;
            } else if (cqe_err) {
                ret_rx_processed += poll_and_process_error_element_rx(cqe_err, pv_fd_ready_array);
            } else {
                compensate_qp_poll_failed();
            }
        }
    } else {
        buff_status_e status = BS_OK;
        uint32_t ret = 0;
        while (ret < m_n_sysvar_cq_poll_batch_max) {
            mem_buf_desc_t *buff = poll(status);
            if (buff) {
                ++ret;
                if (process_cq_element_rx(buff, status)) {
                    if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                        !compensate_qp_poll_success(buff)) {
                        process_recv_buffer(buff, pv_fd_ready_array);
                    }
                }
            } else {
                m_b_was_drained = true;
                break;
            }
        }

        update_global_sn(*p_cq_poll_sn, ret);

        if (likely(ret > 0)) {
            ret_rx_processed += ret;
            m_n_wce_counter += ret;
            m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
        } else {
            compensate_qp_poll_failed();
        }
    }

    return ret_rx_processed;
}

int cq_mgr_mlx5::poll_and_process_element_rx(mem_buf_desc_t **p_desc_lst)
{
    int packets_num = 0;

    if (unlikely(m_rx_hot_buffer == NULL)) {
        int index = m_qp->m_mlx5_qp.rq.tail & (m_qp->m_rx_num_wr - 1);
        m_rx_hot_buffer = (mem_buf_desc_t *)(uintptr_t)m_qp->m_rq_wqe_idx_to_wrid[index];
        m_rx_hot_buffer->rx.context = NULL;
        m_rx_hot_buffer->rx.is_vma_thr = false;
    }
    // prefetch_range((uint8_t*)m_rx_hot_buffer->p_buffer,safe_mce_sys().rx_prefetch_bytes_before_poll);
#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
    RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_READY_POLL]);
#endif // RDTSC_MEASURE_RX_VERBS_READY_POLL

#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
    RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_IDLE_POLL]);
#endif // RDTSC_MEASURE_RX_VERBS_IDLE_POLL

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
    RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL]);
#endif // RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
    vma_mlx5_cqe *cqe_err = NULL;
    vma_mlx5_cqe *cqe = get_cqe(&cqe_err);

    if (likely(cqe)) {
        buff_status_e status = BS_OK;

        ++m_n_wce_counter;
        ++m_qp->m_mlx5_qp.rq.tail;

        cqe_to_mem_buff_desc(cqe, m_rx_hot_buffer, status);

        if (unlikely(++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv)) {
            (void)compensate_qp_poll_success(m_rx_hot_buffer);
        }
        ++packets_num;
        *p_desc_lst = m_rx_hot_buffer;
        m_rx_hot_buffer = NULL;
    } else if (cqe_err) {
        /* Return nothing in case error wc
         * It is difference with poll_and_process_element_rx()
         */
        poll_and_process_error_element_rx(cqe_err, NULL);
        *p_desc_lst = NULL;
    } else {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
        RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_IDLE_POLL]);
#endif

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
        RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL]);
#endif

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
        RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM]);
#endif
        compensate_qp_poll_failed();
    }

    return packets_num;
}

inline void cq_mgr_mlx5::cqe_to_vma_wc(struct vma_mlx5_cqe *cqe, vma_ibv_wc *wc)
{
    struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe;

    switch (cqe->op_own >> 4) {
    case MLX5_CQE_RESP_WR_IMM:
        cq_logerr("IBV_WC_RECV_RDMA_WITH_IMM is not supported");
        break;
    case MLX5_CQE_RESP_SEND:
    case MLX5_CQE_RESP_SEND_IMM:
    case MLX5_CQE_RESP_SEND_INV:
        vma_wc_opcode(*wc) = VMA_IBV_WC_RECV;
        wc->byte_len = ntohl(cqe->byte_cnt);
        wc->status = IBV_WC_SUCCESS;
        return;
    case MLX5_CQE_REQ:
        wc->status = IBV_WC_SUCCESS;
        return;
    default:
        break;
    }

    /* Only IBV_WC_WR_FLUSH_ERR is used in code */
    if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR == ecqe->syndrome) {
        wc->status = IBV_WC_WR_FLUSH_ERR;
    } else {
        wc->status = IBV_WC_GENERAL_ERR;
    }

    wc->vendor_err = ecqe->vendor_err_synd;
}

void cq_mgr_mlx5::handle_sq_wqe_prop(unsigned index)
{
    sq_wqe_prop *p = &m_qp->m_sq_wqe_idx_to_prop[index];
    sq_wqe_prop *prev;

    /*
     * TX completions can be signalled for a set of WQEs as an optimization.
     * Therefore, for every TX completion we may need to handle multiple
     * WQEs. Since every WQE can have various size and the WQE index is
     * wrapped around, we build a linked list to simplify things. Each
     * element of the linked list represents properties of a previously
     * posted WQE.
     *
     * We keep index of the last completed WQE and stop processing the list
     * when we reach the index. This condition is checked in
     * is_sq_wqe_prop_valid().
     *
     * TODO We can move buffers handling here. In this case, we can
     * associate a WQE with a set of scatter-gather buffers and remove
     * fake mem_buf_desct_t object for retransmitted TCP segments.
     * This approach will solve data corruption issue with retransmitted
     * scatter-gather TCP segments.
     */

    do {
        if (p->ti != NULL) {
            xlio_ti *ti = p->ti;
            if (ti->m_callback) {
                ti->m_callback(ti->m_callback_arg);
            }

            ti->put();
            if (unlikely(ti->m_released && ti->m_ref == 0)) {
                m_qp->ti_released(ti);
            }
        }

        prev = p;
        p = p->next;
    } while (p != NULL && m_qp->is_sq_wqe_prop_valid(p, prev));

    m_qp->m_sq_wqe_prop_last_signalled = index;
}

int cq_mgr_mlx5::poll_and_process_error_element_tx(struct vma_mlx5_cqe *cqe, uint64_t *p_cq_poll_sn)
{
    uint16_t wqe_ctr = ntohs(cqe->wqe_counter);
    unsigned index = wqe_ctr & (m_qp->m_tx_num_wr - 1);
    mem_buf_desc_t *buff = NULL;
    vma_ibv_wc wce;

    // spoil the global sn if we have packets ready
    union __attribute__((packed)) {
        uint64_t global_sn;
        struct {
            uint32_t cq_id;
            uint32_t cq_sn;
        } bundle;
    } next_sn;
    next_sn.bundle.cq_sn = ++m_n_cq_poll_sn;
    next_sn.bundle.cq_id = m_cq_id;

    *p_cq_poll_sn = m_n_global_sn = next_sn.global_sn;

    memset(&wce, 0, sizeof(wce));
    if (m_qp->m_sq_wqe_idx_to_prop) {
        wce.wr_id = m_qp->m_sq_wqe_idx_to_prop[index].wr_id;
        cqe_to_vma_wc(cqe, &wce);

        buff = cq_mgr::process_cq_element_tx(&wce);
        if (buff) {
            cq_mgr::process_tx_buffer_list(buff);
        }
        handle_sq_wqe_prop(index);
        return 1;
    }
    return 0;
}

int cq_mgr_mlx5::poll_and_process_element_tx(uint64_t *p_cq_poll_sn)
{
    // Assume locked!!!
    cq_logfuncall("");

    int ret = 0;
    vma_mlx5_cqe *cqe_err = NULL;
    vma_mlx5_cqe *cqe = get_cqe(&cqe_err);

    if (likely(cqe)) {
        uint16_t wqe_ctr = ntohs(cqe->wqe_counter);
        unsigned index = wqe_ctr & (m_qp->m_tx_num_wr - 1);
        mem_buf_desc_t *buff = (mem_buf_desc_t *)(uintptr_t)m_qp->m_sq_wqe_idx_to_prop[index].wr_id;
        // spoil the global sn if we have packets ready
        union __attribute__((packed)) {
            uint64_t global_sn;
            struct {
                uint32_t cq_id;
                uint32_t cq_sn;
            } bundle;
        } next_sn;
        next_sn.bundle.cq_sn = ++m_n_cq_poll_sn;
        next_sn.bundle.cq_id = m_cq_id;

        *p_cq_poll_sn = m_n_global_sn = next_sn.global_sn;

        if (likely(buff != NULL)) {
            cq_mgr::process_tx_buffer_list(buff);
        }
        handle_sq_wqe_prop(index);
        ret = 1;
    } else if (cqe_err) {
        ret = poll_and_process_error_element_tx(cqe_err, p_cq_poll_sn);
    } else {
        *p_cq_poll_sn = m_n_global_sn;
    }

    return ret;
}

void cq_mgr_mlx5::set_qp_rq(qp_mgr *qp)
{
    m_qp = static_cast<qp_mgr_eth_mlx5 *>(qp);

    m_qp->m_rq_wqe_counter = 0; // In case of bonded qp, wqe_counter must be reset to zero
    m_rx_hot_buffer = NULL;

    if (0 != vma_ib_mlx5_get_cq(m_p_ibv_cq, &m_mlx5_cq)) {
        cq_logpanic("vma_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }
    VALGRIND_MAKE_MEM_DEFINED(&m_mlx5_cq, sizeof(m_mlx5_cq));
    cq_logfunc("qp_mgr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", m_qp, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);
}

void cq_mgr_mlx5::add_qp_rx(qp_mgr *qp)
{
    cq_logfunc("");
    set_qp_rq(qp);
    cq_mgr::add_qp_rx(qp);
}

void cq_mgr_mlx5::add_qp_tx(qp_mgr *qp)
{
    // Assume locked!
    cq_mgr::add_qp_tx(qp);
    m_qp = static_cast<qp_mgr_eth_mlx5 *>(qp);

    if (0 != vma_ib_mlx5_get_cq(m_p_ibv_cq, &m_mlx5_cq)) {
        cq_logpanic("vma_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }

    cq_logfunc("qp_mgr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", m_qp, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);
}

int cq_mgr_mlx5::poll_and_process_error_element_rx(struct vma_mlx5_cqe *cqe,
                                                   void *pv_fd_ready_array)
{
    vma_ibv_wc wce;

    memset(&wce, 0, sizeof(wce));
    wce.wr_id = (uintptr_t)m_rx_hot_buffer;
    cqe_to_vma_wc(cqe, &wce);

    ++m_n_wce_counter;
    ++m_qp->m_mlx5_qp.rq.tail;

    m_rx_hot_buffer = cq_mgr::process_cq_element_rx(&wce);
    if (m_rx_hot_buffer) {
        if (vma_wc_opcode(wce) & VMA_IBV_WC_RECV) {
            if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
                !compensate_qp_poll_success(m_rx_hot_buffer)) {
                process_recv_buffer(m_rx_hot_buffer, pv_fd_ready_array);
            }
        }
    }
    m_rx_hot_buffer = NULL;

    return 1;
}

void cq_mgr_mlx5::lro_update_hdr(struct vma_mlx5_cqe *cqe, mem_buf_desc_t *p_rx_wc_buf_desc)
{
    struct ethhdr *p_eth_h = (struct ethhdr *)(p_rx_wc_buf_desc->p_buffer);
    struct iphdr *p_ip_h = NULL;
    struct tcphdr *p_tcp_h = NULL;
    size_t transport_header_len = ETH_HDR_LEN;

    if (p_eth_h->h_proto == htons(ETH_P_8021Q)) {
        transport_header_len = ETH_VLAN_HDR_LEN;
    }

    assert(p_ip_h->protocol == IPPROTO_TCP);
    assert(p_ip_h->version == IPV4_VERSION);

    p_ip_h = (struct iphdr *)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
    p_tcp_h = (struct tcphdr *)((uint8_t *)p_ip_h + (int)(p_ip_h->ihl) * 4);

    if ((cqe->lro_tcppsh_abort_dupack >> 6) & 1) {
        p_tcp_h->psh = 1;
    }

    /* TCP packet <ACK> flag is set, and packet carries no data or
     * TCP packet <ACK> flag is set, and packet carries data
     */
    if ((0x03 == ((cqe->l4_hdr_type_etc >> 4) & 0x7)) ||
        (0x04 == ((cqe->l4_hdr_type_etc >> 4) & 0x7))) {
        p_tcp_h->ack = 1;
        p_tcp_h->ack_seq = cqe->lro_ack_seq_num;
        p_tcp_h->window = cqe->lro_tcp_win;

        /* ignore */
        p_tcp_h->check = 0;
    }

    p_ip_h->ttl = cqe->lro_min_ttl;
    p_ip_h->tot_len = htons(ntohl(cqe->byte_cnt) - transport_header_len);

    /* ignore */
    p_ip_h->check = 0;
}

#endif /* DEFINED_DIRECT_VERBS */
