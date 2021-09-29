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

#include "cq_mgr_mlx5_strq.h"

#if defined(DEFINED_DIRECT_VERBS)

#include <vma/util/valgrind.h>
#include "cq_mgr.inl"
#include "cq_mgr_mlx5.inl"
#include "qp_mgr.h"
#include "qp_mgr_eth_mlx5.h"
#include "ring_simple.h"
#include <cinttypes>

#define MODULE_NAME "cq_mgr_mlx5_strq"

#define cq_logfunc     __log_info_func
#define cq_logdbg      __log_info_dbg
#define cq_logerr      __log_info_err
#define cq_logpanic    __log_info_panic
#define cq_logfuncall  __log_info_funcall

#define CQ_CACHE_MIN_STRIDES 16U
#define MAX_CACHED_BLOCKS 3ULL

cq_strides_cache::cq_strides_cache(ring_slave* owner_ring):
	_compensation_level(std::max(CQ_CACHE_MIN_STRIDES, safe_mce_sys().strq_strides_compensation_level)),
	_retrieve_vec(_compensation_level), _return_vec(_compensation_level), _block_vec(MAX_CACHED_BLOCKS, _return_vec),
	_owner_ring(owner_ring)
{
	get_from_global_pool();
	assign_return_vec_ptrs();
}

cq_strides_cache::~cq_strides_cache()
{
	while (_block_vec_used-- > 1U)
		g_buffer_pool_rx_stride->put_buffers_thread_safe(
			_block_vec[_block_vec_used].data(), _block_vec[_block_vec_used].size());

	g_buffer_pool_rx_stride->put_buffers_thread_safe(_retrieve_ptr, _retrieve_ptr_end - _retrieve_ptr + 1U);
	g_buffer_pool_rx_stride->put_buffers_thread_safe(_return_vec.data(), _return_ptr - _return_vec.data());
}

mem_buf_desc_t* cq_strides_cache::next_stride()
{
	if (unlikely(_retrieve_ptr > _retrieve_ptr_end)) {
		if (likely(_block_vec_used > 0U)) {
			_block_vec[--_block_vec_used].swap(_retrieve_vec);
			assign_retrieve_vec_ptrs();
		} else {
			get_from_global_pool();
		}
	}

	return *_retrieve_ptr++;
}

void cq_strides_cache::return_stride(mem_buf_desc_t* desc)
{
	if (unlikely(_return_ptr > _return_ptr_end)) {
		_block_vec[_block_vec_used++].swap(_return_vec); // Swap the empty new vector with the full _return_vec.
		if (_block_vec_used >= MAX_CACHED_BLOCKS) {
			--_block_vec_used;
			g_buffer_pool_rx_stride->put_buffers_thread_safe(
				_block_vec[_block_vec_used].data(), _block_vec[_block_vec_used].size());
		}

		assign_return_vec_ptrs();
	}

	*_return_ptr++ = desc;
}

void cq_strides_cache::get_from_global_pool()
{
	descq_t deque;
	if (!g_buffer_pool_rx_stride->get_buffers_thread_safe(deque, _owner_ring, _compensation_level, 0U))
		// This pool should be an infinite pool
		__log_info_panic("Unable to retrieve strides from global pool, Free: %zu, Requested: %zu",
			g_buffer_pool_rx_stride->get_free_count(), _compensation_level);

	if (unlikely(deque.size() > _retrieve_vec.size() || deque.size() <= 0U))
		// If we get here it's a bug in get_buffers_thread_safe()
		_retrieve_vec.resize(std::max(deque.size(), static_cast<size_t>(CQ_CACHE_MIN_STRIDES)));

	assign_retrieve_vec_ptrs();

	while (!deque.empty())
		*_retrieve_ptr++ = deque.get_and_pop_front();

	_retrieve_ptr = _retrieve_vec.data();
}

void cq_strides_cache::assign_retrieve_vec_ptrs()
{
	_retrieve_ptr = _retrieve_vec.data();
	_retrieve_ptr_end = &_retrieve_vec.data()[_retrieve_vec.size() - 1U];
}

void cq_strides_cache::assign_return_vec_ptrs()
{
	_return_ptr = _return_vec.data();
	_return_ptr_end = &_return_vec.data()[_return_vec.size() - 1U];
}

cq_mgr_mlx5_strq::cq_mgr_mlx5_strq(
        ring_simple* p_ring, ib_ctx_handler* p_ib_ctx_handler, uint32_t cq_size,
        uint32_t stride_size_bytes, uint32_t strides_num,
        struct ibv_comp_channel* p_comp_event_channel, bool call_configure):
	cq_mgr_mlx5(p_ring, p_ib_ctx_handler, cq_size, p_comp_event_channel, true, call_configure),
	_stride_cache(p_ring), _stride_size_bytes(stride_size_bytes), _strides_num(strides_num), _wqe_buff_size_bytes(strides_num * stride_size_bytes)
{
	cq_logfunc("");
	m_n_sysvar_rx_prefetch_bytes_before_poll = std::min(m_n_sysvar_rx_prefetch_bytes_before_poll, stride_size_bytes);
}

cq_mgr_mlx5_strq::~cq_mgr_mlx5_strq()
{
	cq_logfunc("");
	cq_logdbg("destroying CQ STRQ");

	if (m_rx_buffs_rdy_for_free_head) {
		reclaim_recv_buffer_helper(m_rx_buffs_rdy_for_free_head);
		m_rx_buffs_rdy_for_free_head = m_rx_buffs_rdy_for_free_tail = nullptr;
	}

	if (m_rx_queue.size()) {
		cq_logdbg("Clearing %zu stride objects)", m_rx_queue.size());

		while (!m_rx_queue.empty())
			reclaim_recv_buffer_helper(m_rx_queue.get_and_pop_front());

		m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
	}

	if (_hot_buffer_stride)
		_stride_cache.return_stride(_hot_buffer_stride);
}

uint32_t cq_mgr_mlx5_strq::clean_cq()
{
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;
	mem_buf_desc_t* buff;

	/* Sanity check for cq: initialization of tx and rx cq has difference:
	* rx - is done in qp_mgr::up()
	* as a result rx cq can be created but not initialized
	*/
	if (NULL == m_qp) return 0;

	mem_buf_desc_t* stride_buf = nullptr;
	buff_status_e status = BS_OK;
	while ((buff = poll(status, stride_buf)) || stride_buf) {
		if (stride_buf && process_cq_element_rx(stride_buf, status))
			m_rx_queue.push_back(stride_buf);

		++ret_total;
		stride_buf = nullptr;
	}

	update_global_sn(cq_poll_sn, ret_total);

	return ret_total;
}

mem_buf_desc_t* cq_mgr_mlx5_strq::poll(enum buff_status_e& status, mem_buf_desc_t*& buff_stride)
{
	mem_buf_desc_t *buff = NULL;

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
	RDTSC_TAKE_END(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL);
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL

#if defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) || defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
	RDTSC_TAKE_START_RX_VERBS_POLL(RDTSC_FLOW_RX_VERBS_READY_POLL, RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif //RDTSC_MEASURE_RX_VERBS_READY_POLL || RDTSC_MEASURE_RX_VERBS_IDLE_POLL

	if (unlikely(!m_rx_hot_buffer)) {
		if (likely(m_qp->m_mlx5_qp.rq.tail != (m_qp->m_mlx5_qp.rq.head))) {
			uint32_t index = m_qp->m_mlx5_qp.rq.tail & (m_qp_rec.qp->m_rx_num_wr - 1);
			m_rx_hot_buffer = (mem_buf_desc_t *)m_qp->m_rq_wqe_idx_to_wrid[index];
			m_rx_hot_buffer->set_ref_count(_strides_num);
			m_qp->m_rq_wqe_idx_to_wrid[index] = 0;
			prefetch((void*)m_rx_hot_buffer);
			prefetch((uint8_t*)m_mlx5_cq.cq_buf + ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));
		} else {
#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
			RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#endif

#if defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) || defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
			RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL,
					RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM);
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL || RDTSC_MEASURE_RX_CQE_RECEIVEFROM
			/* If rq_tail and rq_head are pointing to the same wqe,
			 * the wq is empty and there is no cqe to be received */
			return NULL;
		}
	}

	if (likely(!_hot_buffer_stride)) {
		_hot_buffer_stride = _stride_cache.next_stride();
		prefetch((void*)_hot_buffer_stride);
	}

	vma_mlx5_cqe *cqe = check_cqe();
	if (likely(cqe)) {
		/* Update the consumer index */
		++m_mlx5_cq.cq_ci;
		rmb();

		bool is_filler = false;
		bool is_wqe_complete = cqe_to_mem_buff_desc(cqe, status, is_filler);

		*m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci & 0xffffff);

		if (is_wqe_complete) {
			++m_qp->m_mlx5_qp.rq.tail;
			buff = m_rx_hot_buffer;
			m_rx_hot_buffer = NULL;
			if (likely(status == BS_OK))
				++m_p_cq_stat->n_rx_consumed_rwqe_count;
		}

		if (likely(!is_filler)) {
			++m_p_cq_stat->n_rx_packet_count;
			m_p_cq_stat->n_rx_stride_count += _hot_buffer_stride->strides_num;
			m_p_cq_stat->n_rx_max_stirde_per_packet = std::max(m_p_cq_stat->n_rx_max_stirde_per_packet, _hot_buffer_stride->strides_num);
			buff_stride = _hot_buffer_stride;
			_hot_buffer_stride = nullptr;
		} else if (status != BS_CQE_INVALID) {
			reclaim_recv_buffer_helper(_hot_buffer_stride);
			_hot_buffer_stride = nullptr;
		}

#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
		RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_READY_POLL);
#endif //RDTSC_MEASURE_RX_VERBS_READY_POLL

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
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL || RDTSC_MEASURE_RX_CQE_RECEIVEFROM

		prefetch((void*)_hot_buffer_stride);
	}

	prefetch((uint8_t*)m_mlx5_cq.cq_buf + ((m_mlx5_cq.cq_ci & (m_mlx5_cq.cqe_count - 1)) << m_mlx5_cq.cqe_size_log));

	return buff;
}

inline bool cq_mgr_mlx5_strq::cqe_to_mem_buff_desc(
	struct vma_mlx5_cqe *cqe, enum buff_status_e &status, bool& is_filler)
{
	cq_mgr_mlx5::cqe_to_mem_buff_desc(cqe, _hot_buffer_stride, status);
	uint32_t host_byte_cnt = ntohl(cqe->byte_cnt);
	_hot_buffer_stride->strides_num = ((host_byte_cnt >> 16) & 0x00003FFF);
	_hot_buffer_stride->lwip_pbuf.pbuf.desc.attr_pbuf_desc = PBUF_DESC_STRIDE;
	_hot_buffer_stride->lwip_pbuf.pbuf.desc.mdesc = m_rx_hot_buffer;

	if (likely(BS_OK == status)) {
		is_filler = (host_byte_cnt >> 31 != 0U ? true : false);
		_hot_buffer_stride->sz_data = host_byte_cnt & 0x0000FFFFU; // In case of a Filler/Error this size is invalid.
		_hot_buffer_stride->p_buffer = m_rx_hot_buffer->p_buffer + _current_wqe_consumed_bytes; //(_stride_size_bytes * ntohs(cqe->wqe_counter))
		_hot_buffer_stride->sz_buffer = _hot_buffer_stride->strides_num * _stride_size_bytes;
		_current_wqe_consumed_bytes += _hot_buffer_stride->sz_buffer;
	} else if (likely(BS_CQE_INVALID != status)) {
		is_filler = true;
		_current_wqe_consumed_bytes = _wqe_buff_size_bytes;
		_hot_buffer_stride->sz_data = 0U;
		_hot_buffer_stride->p_buffer = nullptr;
		_hot_buffer_stride->sz_buffer = 0U;

		if (_hot_buffer_stride->strides_num == 0U)
			_hot_buffer_stride->strides_num = _strides_num;
	} else {
		return false;
	}

	cq_logfunc("STRQ CQE. Status: %d, WQE-ID: %hu, Is-Filler: %" PRIu32 ", Orig-HBC: %" PRIu32
		", Data-Size: %" PRIu32 ", Strides: %hu, Consumed-Bytes: %" PRIu32 ", RX-HB: %p, RX-HB-SZ: %zu\n",
		static_cast<int>(status), cqe->wqe_id, (host_byte_cnt >> 31), cqe->byte_cnt, (host_byte_cnt & 0x0000FFFFU),
		_hot_buffer_stride->strides_num, _current_wqe_consumed_bytes, m_rx_hot_buffer, m_rx_hot_buffer->sz_buffer);
	vlog_print_buffer(VLOG_FINE, "STRQ CQE. Data: ", "\n",
		reinterpret_cast<const char*>(_hot_buffer_stride->p_buffer), min(112, static_cast<int>(_hot_buffer_stride->sz_data)));

	if (_current_wqe_consumed_bytes >= _wqe_buff_size_bytes) {
		_current_wqe_consumed_bytes = 0;
		return true;
	}

	return false;
}

int cq_mgr_mlx5_strq::drain_and_proccess_sockextreme(uintptr_t* p_recycle_buffers_last_wr_id)
{
	uint32_t ret_total = 0;
	NOT_IN_USE(p_recycle_buffers_last_wr_id);
	/*while (((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) && (!m_b_was_drained)) ||
		(p_recycle_buffers_last_wr_id)) {
		int ret = 0;
		vma_mlx5_cqe *cqe_arr[MCE_MAX_CQ_POLL_BATCH];

		for (int i = 0; i < MCE_MAX_CQ_POLL_BATCH; ++i)
		{
			cqe_arr[i] = get_cqe();
			if (cqe_arr[i]) {
				++ret;
				wmb();
				*m_mlx5_cq.dbrec = htonl(m_mlx5_cq.cq_ci);
				if (m_b_is_rx) {
					++m_qp->m_mlx5_qp.rq.tail;
				}
			}
			else {
				break;
			}
		}

		if (!ret) {
			m_b_was_drained = true;
			return ret_total;
		}


		m_n_wce_counter += ret;
		if (ret < MCE_MAX_CQ_POLL_BATCH)
			m_b_was_drained = true;

		for (int i = 0; i < ret; i++) {
			uint32_t wqe_sz = 0;
			vma_mlx5_cqe *cqe = cqe_arr[i];
			vma_ibv_wc wce;

			uint16_t wqe_ctr = ntohs(cqe->wqe_counter);
			if (m_b_is_rx) {
				wqe_sz = m_qp->m_rx_num_wr;
			}
			else {
				wqe_sz = m_qp->m_tx_num_wr;
			}

			int index = wqe_ctr & (wqe_sz - 1);

			// We need to processes rx data in case
			// wce.status == IBV_WC_SUCCESS
			// and release buffers to rx pool
			// in case failure
			m_rx_hot_buffer = (mem_buf_desc_t*)(uintptr_t)m_qp->m_rq_wqe_idx_to_wrid[index];
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
					if (m_transport_type == VMA_TRANSPORT_IB) {
						procces_now = is_ib_tcp_frame(m_rx_hot_buffer);
					}
					// We process immediately all non udp/ip traffic..
					if (procces_now) {
						m_rx_hot_buffer->rx.is_vma_thr = true;
						if ((++m_qp_rec.debt < (int)m_n_sysvar_rx_num_wr_to_post_recv) ||
							!compensate_qp_poll_success(m_rx_hot_buffer)) {
							process_recv_buffer(m_rx_hot_buffer, NULL);
						}
					}
					else { //udp/ip traffic we just put in the cq's rx queue
						m_rx_queue.push_back(m_rx_hot_buffer);
						mem_buf_desc_t* buff_cur = m_rx_queue.get_and_pop_front();
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
	}*/

	return ret_total;
}

int cq_mgr_mlx5_strq::drain_and_proccess(uintptr_t* p_recycle_buffers_last_wr_id)
{
	cq_logfuncall("cq was %s drained. %d processed wce since last check. %d wce in m_rx_queue",
		(m_b_was_drained ? "" : "not "), m_n_wce_counter, m_rx_queue.size());

	// CQ polling loop until max wce limit is reached for this interval or CQ is drained
	uint32_t ret_total = 0;
	uint64_t cq_poll_sn = 0;

	// drain_and_proccess() is mainly called in following cases as
	// Internal thread:
	//   Frequency of real polling can be controlled by
	//   VMA_PROGRESS_ENGINE_INTERVAL and VMA_PROGRESS_ENGINE_WCE_MAX.
	// socketxtreme:
	//   User does socketxtreme_poll()
	// Cleanup:
	//   QP down logic to release rx buffers should force polling to do this.
	//   Not null argument indicates one.

	if (m_b_sysvar_enable_socketxtreme) {
		ret_total = drain_and_proccess_sockextreme(p_recycle_buffers_last_wr_id);
	} else {
		while (((m_n_sysvar_progress_engine_wce_max > m_n_wce_counter) && (!m_b_was_drained)) ||
				p_recycle_buffers_last_wr_id) {
			buff_status_e status = BS_OK;
			mem_buf_desc_t* buff = nullptr;
			mem_buf_desc_t* buff_wqe = poll(status, buff);
			if (!buff && !buff_wqe) {
				update_global_sn(cq_poll_sn, ret_total);
				m_b_was_drained = true;
				m_p_ring->m_gro_mgr.flush_all(nullptr);
				return ret_total;
			}

			if (buff_wqe && (++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv) && !p_recycle_buffers_last_wr_id)
				compensate_qp_poll_failed(); // Reuse this method as success.

			// Handle a stride. It can be that we have got a Filler CQE, in this case buff is null.
			if (buff) {
				++m_n_wce_counter; // Actually strides count.

				if (process_cq_element_rx(buff, status)) {
					if (p_recycle_buffers_last_wr_id) {
						m_p_cq_stat->n_rx_pkt_drop++;
						reclaim_recv_buffer_helper(buff);
					} else {
						bool procces_now = (m_transport_type == VMA_TRANSPORT_ETH ? is_eth_tcp_frame(buff) : false);

						// We process immediately all non udp/ip traffic..
						if (procces_now) {
							buff->rx.is_vma_thr = true;
							process_recv_buffer(buff, nullptr);
						} else { // udp/ip traffic we just put in the cq's rx queue
							m_rx_queue.push_back(buff);
						}
					}
				}

				++ret_total;
			}

			if (p_recycle_buffers_last_wr_id && buff_wqe)
				*p_recycle_buffers_last_wr_id = (uintptr_t)buff_wqe;
		}

		update_global_sn(cq_poll_sn, ret_total);

		m_p_ring->m_gro_mgr.flush_all(nullptr);
	}

	m_n_wce_counter = 0; // Actually strides count.
	m_b_was_drained = false;

	// Update cq statistics
	m_p_cq_stat->n_rx_sw_queue_len = m_rx_queue.size();
	m_p_cq_stat->n_rx_drained_at_once_max = std::max(ret_total, m_p_cq_stat->n_rx_drained_at_once_max);

	return ret_total;
}

mem_buf_desc_t* cq_mgr_mlx5_strq::process_cq_element_rx(mem_buf_desc_t* p_mem_buf_desc, enum buff_status_e status)
{
	/* Assume locked!!! */
	cq_logfuncall("");

	/* we use context to verify that on reclaim rx buffer path we return the buffer to the right CQ */
	p_mem_buf_desc->rx.is_vma_thr = false;
	p_mem_buf_desc->rx.context = nullptr;
	p_mem_buf_desc->rx.socketxtreme_polled = false;

	if (unlikely(status != BS_OK)) {
		reclaim_recv_buffer_helper(p_mem_buf_desc);
		return nullptr;
	}

	VALGRIND_MAKE_MEM_DEFINED(p_mem_buf_desc->p_buffer, p_mem_buf_desc->sz_data);

	prefetch_range(
		(uint8_t*)p_mem_buf_desc->p_buffer + m_sz_transport_header,
		std::min(p_mem_buf_desc->sz_data - m_sz_transport_header, (size_t)m_n_sysvar_rx_prefetch_bytes));

	return p_mem_buf_desc;
}

int cq_mgr_mlx5_strq::poll_and_process_element_rx_sockextreme(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	uint32_t ret_rx_processed = 0U;
	NOT_IN_USE(p_cq_poll_sn);
	NOT_IN_USE(pv_fd_ready_array);
	/*if (unlikely(m_rx_hot_buffer == NULL)) {
		int index = m_qp->m_mlx5_qp.rq.tail & (m_qp->m_rx_num_wr - 1);
		m_rx_hot_buffer = (mem_buf_desc_t*)(uintptr_t)m_qp->m_rq_wqe_idx_to_wrid[index];
		m_rx_hot_buffer->rx.context = NULL;
		m_rx_hot_buffer->rx.is_vma_thr = false;
		m_rx_hot_buffer->rx.socketxtreme_polled = false;
	}
	else {
		vma_mlx5_cqe *cqe_err = NULL;
		vma_mlx5_cqe *cqe = get_cqe(&cqe_err);

		if (likely(cqe)) {
			++m_n_wce_counter;
			++m_qp->m_mlx5_qp.rq.tail;
			m_rx_hot_buffer->sz_data = ntohl(cqe->byte_cnt);
			m_rx_hot_buffer->rx.flow_tag_id = vma_get_flow_tag(cqe);
			m_rx_hot_buffer->rx.is_sw_csum_need = !(m_b_is_rx_hw_csum_on &&
					(cqe->hds_ip_ext & MLX5_CQE_L4_OK) && (cqe->hds_ip_ext & MLX5_CQE_L3_OK));

			if (unlikely(++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv)) {
				(void)compensate_qp_poll_success(m_rx_hot_buffer);
			}
			process_recv_buffer(m_rx_hot_buffer, pv_fd_ready_array);
			++ret_rx_processed;
			m_rx_hot_buffer = NULL;
		}
		else if (cqe_err) {
			ret_rx_processed += poll_and_process_error_element_rx(cqe_err, pv_fd_ready_array);
		}
		else {
			compensate_qp_poll_failed();
		}

	}*/

	return ret_rx_processed;
}

int cq_mgr_mlx5_strq::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array)
{
	/* Assume locked!!! */
	cq_logfuncall("");

	uint32_t ret_rx_processed = process_recv_queue(pv_fd_ready_array);
	if (unlikely(ret_rx_processed >= m_n_sysvar_cq_poll_batch_max)) {
		m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
		return ret_rx_processed;
	}

	if (m_n_sysvar_rx_prefetch_bytes_before_poll && m_rx_hot_buffer)
		prefetch_range((uint8_t*)m_rx_hot_buffer->p_buffer + _current_wqe_consumed_bytes, m_n_sysvar_rx_prefetch_bytes_before_poll);

	if (m_b_sysvar_enable_socketxtreme) {
		ret_rx_processed += poll_and_process_element_rx_sockextreme(p_cq_poll_sn, pv_fd_ready_array);
	} else {
		buff_status_e status = BS_OK;
		uint32_t ret = 0;
		while (ret < m_n_sysvar_cq_poll_batch_max) {
			mem_buf_desc_t* buff = nullptr;
			mem_buf_desc_t* buff_wqe = poll(status, buff);

			if (buff_wqe && (++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv))
				compensate_qp_poll_failed(); // Reuse this method as success.

			if (buff) {
				++ret;
				if (process_cq_element_rx(buff, status))
					process_recv_buffer(buff, pv_fd_ready_array);
			} else if (!buff_wqe) {
				m_b_was_drained = true;
				break;
			}
		}

		update_global_sn(*p_cq_poll_sn, ret);

		if (likely(ret > 0)) {
			ret_rx_processed += ret;
			m_n_wce_counter += ret; // Actually strides count.
			m_p_ring->m_gro_mgr.flush_all(pv_fd_ready_array);
		} else {
			compensate_qp_poll_failed();
		}
	}

	return ret_rx_processed;
}

void cq_mgr_mlx5_strq::add_qp_rx(qp_mgr* qp)
{
	cq_logfunc("");
	set_qp_rq(qp);
	_hot_buffer_stride = nullptr;
	_current_wqe_consumed_bytes = 0U;
	cq_mgr::add_qp_rx(qp);
}

void cq_mgr_mlx5_strq::mem_buf_desc_return_to_owner(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array)
{
	cq_logfuncall("");
	NOT_IN_USE(pv_fd_ready_array);
	cq_mgr::reclaim_recv_buffer_helper(p_mem_buf_desc);
}

void cq_mgr_mlx5_strq::statistics_print()
{
	cq_mgr::statistics_print();
}

void cq_mgr_mlx5_strq::reclaim_recv_buffer_helper(mem_buf_desc_t* buff)
{
	if (buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.pbuf.ref-- <= 1)) {
		if (likely(buff->p_desc_owner == m_p_ring)) {
			mem_buf_desc_t* temp = nullptr;
			while (buff) {
				if (unlikely(buff->lwip_pbuf.pbuf.desc.attr_pbuf_desc != PBUF_DESC_STRIDE)) {
					__log_info_err("CQ STRQ reclaim_recv_buffer_helper with incompatible mem_buf_desc_t object");
					continue;
				}

				mem_buf_desc_t* rwqe = reinterpret_cast<mem_buf_desc_t*>(buff->lwip_pbuf.pbuf.desc.mdesc);
				if (buff->strides_num == rwqe->add_ref_count(-buff->strides_num)) // Is last stride.
					cq_mgr::reclaim_recv_buffer_helper(rwqe);

				VLIST_DEBUG_CQ_MGR_PRINT_ERROR_IS_MEMBER;
				temp = buff;
				buff = temp->p_next_desc;
				temp->p_next_desc = nullptr;
				temp->p_prev_desc = nullptr;
				temp->reset_ref_count();
				memset(&temp->rx, 0, sizeof(temp->rx));
				free_lwip_pbuf(&temp->lwip_pbuf);
				_stride_cache.return_stride(temp);
			}

			m_p_cq_stat->n_buffer_pool_len = m_rx_pool.size();
		} else {
			cq_logfunc("Stride returned to wrong CQ");
			g_buffer_pool_rx_ptr->put_buffers_thread_safe(buff);
		}
	}
}

// Sockextreme only.
int cq_mgr_mlx5_strq::poll_and_process_element_rx(mem_buf_desc_t **p_desc_lst)
{
	int packets_num = 0;
	NOT_IN_USE(p_desc_lst);
	/*if (unlikely(m_rx_hot_buffer == NULL)) {
		int index = m_qp->m_mlx5_qp.rq.tail & (m_qp->m_rx_num_wr - 1);
		m_rx_hot_buffer = (mem_buf_desc_t*)(uintptr_t)m_qp->m_rq_wqe_idx_to_wrid[index];
		m_rx_hot_buffer->rx.context = NULL;
		m_rx_hot_buffer->rx.is_vma_thr = false;
	}
	//prefetch_range((uint8_t*)m_rx_hot_buffer->p_buffer,safe_mce_sys().rx_prefetch_bytes_before_poll);
#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_READY_POLL]);
#endif //RDTSC_MEASURE_RX_VERBS_READY_POLL

#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VERBS_IDLE_POLL]);
#endif //RDTSC_MEASURE_RX_VERBS_IDLE_POLL

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL]);
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
	vma_mlx5_cqe *cqe_err = NULL;
	vma_mlx5_cqe *cqe = get_cqe(&cqe_err);

	if (likely(cqe)) {
		++m_n_wce_counter; // Actually strides count.
		++m_qp->m_mlx5_qp.rq.tail;
		m_rx_hot_buffer->sz_data = ntohl(cqe->byte_cnt);
		m_rx_hot_buffer->rx.hw_raw_timestamp = ntohll(cqe->timestamp);
		m_rx_hot_buffer->rx.flow_tag_id = vma_get_flow_tag(cqe);

		m_rx_hot_buffer->rx.is_sw_csum_need = !(m_b_is_rx_hw_csum_on && (cqe->hds_ip_ext & MLX5_CQE_L4_OK) && (cqe->hds_ip_ext & MLX5_CQE_L3_OK));

		if (unlikely(++m_qp_rec.debt >= (int)m_n_sysvar_rx_num_wr_to_post_recv)) {
			(void)compensate_qp_poll_success(m_rx_hot_buffer);
		}
		++packets_num;
		*p_desc_lst = m_rx_hot_buffer;
		m_rx_hot_buffer = NULL;
	}
	else if (cqe_err) {
		// Return nothing in case error wc
		// It is difference with poll_and_process_element_rx()
		poll_and_process_error_element_rx(cqe_err, NULL);
		*p_desc_lst = NULL;
	}
	else {
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
	}*/

	return packets_num;

}

// Sockextreme only.
inline void cq_mgr_mlx5_strq::cqe_to_vma_wc_sockextreme(struct vma_mlx5_cqe *cqe, vma_ibv_wc *wc)
{
	cq_mgr_mlx5::cqe_to_vma_wc(cqe, wc);

	/*if (likely(IBV_WC_SUCCESS == wc->status) && vma_wc_opcode(*wc) == VMA_IBV_WC_RECV) {

	}*/
}

// Sockextreme only
int cq_mgr_mlx5_strq::poll_and_process_error_element_rx_sockextreme(struct vma_mlx5_cqe *cqe, void* pv_fd_ready_array)
{
	NOT_IN_USE(cqe);
	NOT_IN_USE(pv_fd_ready_array);
	/*vma_ibv_wc wce;

	memset(&wce, 0, sizeof(wce));
	wce.wr_id = (uintptr_t)m_rx_hot_buffer;
	cqe_to_vma_wc(cqe, &wce);

	++m_n_wce_counter; // Actually strides count.
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
	m_rx_hot_buffer = NULL;*/

	return 1;
}

#endif /* DEFINED_DIRECT_VERBS */
