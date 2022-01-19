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

#ifndef VMA_STATS_H
#define VMA_STATS_H

#include <stddef.h>
#include <string.h>
#include <bitset>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vlogger/vlogger.h>
#include <vma/xlio_extra.h>
#include <vma/util/sock_addr.h>
#include <assert.h>

#define NUM_OF_SUPPORTED_CQS         16
#define NUM_OF_SUPPORTED_RINGS       16
#define NUM_OF_SUPPORTED_BPOOLS      4
#define NUM_OF_SUPPORTED_EPFDS       32
#define SHMEM_STATS_SIZE(fds_num)    sizeof(sh_mem_t) + (fds_num * sizeof(socket_instance_block_t))
#define FILE_NAME_MAX_SIZE           (NAME_MAX + 1)
#define MC_TABLE_SIZE                1024
#define MAP_SH_MEM(var, sh_stats)    var = (sh_mem_t *)sh_stats
#define STATS_PUBLISHER_TIMER_PERIOD 10 // publisher will check for stats request every 10 msec
#define STATS_READER_DELAY                                                                         \
    STATS_PUBLISHER_TIMER_PERIOD + 5 // reader will wait for vma to wakeup and write statistics to
                                     // shmem (with extra 5 msec overhead)
#define STATS_FD_STATISTICS_DISABLED          -1
#define STATS_FD_STATISTICS_LOG_LEVEL_DEFAULT VLOG_DEFAULT

// statistic file
extern FILE *g_stats_file;

// Common iomux stats
typedef struct {
    pid_t threadid_last;
    uint32_t n_iomux_poll_hit;
    uint32_t n_iomux_poll_miss;
    uint32_t n_iomux_timeouts;
    uint32_t n_iomux_errors;
    uint32_t n_iomux_rx_ready;
    uint32_t n_iomux_os_rx_ready;
    uint32_t n_iomux_polling_time;
} iomux_func_stats_t;

typedef enum { e_totals = 1, e_deltas } print_details_mode_t;

typedef enum { e_basic = 1, e_medium, e_full, e_mc_groups, e_netstat_like } view_mode_t;

typedef enum { e_by_pid_str, e_by_app_name, e_by_runn_proccess } proc_ident_mode_t;

struct user_params_t {
    int interval;
    print_details_mode_t print_details_mode;
    view_mode_t view_mode;
    bool forbid_cleaning;
    vlog_levels_t vma_log_level;
    int vma_details_level;
    bool zero_counters;
    proc_ident_mode_t proc_ident_mode;
    bool write_auth;
    int cycles;
    int fd_dump;
    vlog_levels_t fd_dump_log_level;
    std::string vma_stats_path;
};

extern user_params_t user_params;

// Epoll group stats
typedef struct {
    bool enabled;
    int epfd;
    iomux_func_stats_t stats;
} epoll_stats_t;

// iomux function stat info
typedef struct {
    iomux_func_stats_t poll;
    iomux_func_stats_t select;
    epoll_stats_t epoll[NUM_OF_SUPPORTED_EPFDS];
} iomux_stats_t;

// multicast stat info
typedef struct {
    uint32_t sock_num;
    in_addr_t mc_grp;
} mc_tbl_entry_t;

typedef struct {
    uint16_t max_grp_num;
    mc_tbl_entry_t mc_grp_tbl[MC_TABLE_SIZE];
} mc_grp_info_t;

// socket stat info
typedef struct {
    uint32_t n_rx_packets;
    uint32_t n_rx_bytes;
    uint32_t n_rx_poll_hit;
    uint32_t n_rx_poll_miss;
    uint32_t n_rx_ready_pkt_max;
    uint32_t n_rx_ready_byte_drop;
    uint32_t n_rx_ready_pkt_drop;
    uint32_t n_rx_ready_byte_max;
    uint32_t n_rx_errors;
    uint32_t n_rx_eagain;
    uint32_t n_rx_os_packets;
    uint32_t n_rx_os_bytes;
    uint32_t n_rx_poll_os_hit;
    uint32_t n_rx_os_errors;
    uint32_t n_rx_os_eagain;
    uint32_t n_rx_migrations;
    uint32_t n_tx_sent_pkt_count;
    uint32_t n_tx_sent_byte_count;
    uint32_t n_tx_errors;
    uint32_t n_tx_eagain;
    uint32_t n_tx_retransmits;
    uint32_t n_tx_os_packets;
    uint32_t n_tx_os_bytes;
    uint32_t n_tx_os_errors;
    uint32_t n_tx_os_eagain;
    uint32_t n_tx_migrations;
    uint32_t n_tx_dummy;
    uint32_t n_tx_sendfile_fallbacks;
    uint32_t n_tx_sendfile_overflows;
} socket_counters_t;

#ifdef DEFINED_UTLS
typedef struct {
    uint32_t n_tls_tx_records;
    uint32_t n_tls_tx_bytes;
    uint32_t n_tls_tx_resync;
    uint32_t n_tls_tx_resync_replay;
    uint32_t n_tls_rx_records;
    uint32_t n_tls_rx_records_enc;
    uint32_t n_tls_rx_records_partial;
    uint32_t n_tls_rx_bytes;
    uint32_t n_tls_rx_resync;
} socket_tls_counters_t;
#endif /* DEFINED_UTLS */

typedef struct {
    uint64_t n_strq_total_strides;
    uint32_t n_strq_max_strides_per_packet;
} socket_strq_counters_t;

typedef struct socket_stats_t {
    int fd;
    uint32_t inode;
    uint32_t tcp_state; // enum tcp_state
    uint8_t socket_type; // SOCK_STREAM, SOCK_DGRAM, ...
    bool padding1;
    sa_family_t sa_family;
    bool b_is_offloaded;
    bool b_blocking;
    bool b_mc_loop;
    bool padding2;
    in_port_t bound_port;
    in_port_t connected_port;
    ip_address bound_if;
    ip_address connected_ip;
    ip_address mc_tx_if;
    pid_t threadid_last_rx;
    pid_t threadid_last_tx;
    uint32_t n_rx_ready_pkt_count;
    uint32_t n_rx_ready_byte_limit;
    uint64_t n_rx_ready_byte_count;
    uint64_t n_tx_ready_byte_count;
    uint32_t n_rx_zcopy_pkt_count;
    socket_counters_t counters;
#ifdef DEFINED_UTLS
    bool tls_tx_offload;
    bool tls_rx_offload;
    uint16_t tls_version;
    uint16_t tls_cipher;
    socket_tls_counters_t tls_counters;
#endif /* DEFINED_UTLS */
    socket_strq_counters_t strq_counters;
    std::bitset<MC_TABLE_SIZE> mc_grp_map;
    ring_logic_t ring_alloc_logic_rx;
    ring_logic_t ring_alloc_logic_tx;
    uint64_t ring_user_id_rx;
    uint64_t ring_user_id_tx;

    void reset()
    {
        fd = 0;
        inode = tcp_state = 0;
        socket_type = 0;
        sa_family = 0;
        b_is_offloaded = b_blocking = b_mc_loop = false;
        bound_if = connected_ip = mc_tx_if = ip_address(in6addr_any);
        bound_port = connected_port = (in_port_t)0;
        threadid_last_rx = threadid_last_tx = pid_t(0);
        n_rx_ready_pkt_count = n_rx_ready_byte_count = n_rx_ready_byte_limit =
            n_rx_zcopy_pkt_count = n_tx_ready_byte_count = 0;
        memset(&counters, 0, sizeof(counters));
#ifdef DEFINED_UTLS
        tls_tx_offload = tls_rx_offload = false;
        tls_version = tls_cipher = 0;
        memset(&tls_counters, 0, sizeof(tls_counters));
#endif /* DEFINED_UTLS */
        memset(&strq_counters, 0, sizeof(strq_counters));
        mc_grp_map.reset();
        ring_user_id_rx = ring_user_id_tx = 0;
        ring_alloc_logic_rx = ring_alloc_logic_tx = RING_LOGIC_PER_INTERFACE;
        padding1 = padding2 = 0;
    };

    void set_bound_if(sock_addr &sock)
    {
        sa_family = sock.get_sa_family();
        bound_if = sock.get_ip_addr();
    }

    void set_connected_ip(sock_addr &sock)
    {
        sa_family = sock.get_sa_family();
        connected_ip = sock.get_ip_addr();
    }

    void set_mc_tx_if(sock_addr &sock)
    {
        sa_family = sock.get_sa_family();
        mc_tx_if = sock.get_ip_addr();
    }

    // [TODO IPV6] Temporary - until sockinfo_tcp will support IPv6
    void set_bound_if(in_addr_t ipv4)
    {
        sa_family = AF_INET;
        bound_if = ipv4;
    }

    socket_stats_t()
        : bound_if(in6addr_any)
        , connected_ip(in6addr_any)
        , mc_tx_if(in6addr_any)
    {
        reset();
    };
} socket_stats_t;

typedef struct {
    bool b_enabled;
    socket_stats_t skt_stats;

    void reset()
    {
        b_enabled = false;
        skt_stats.reset();
    }
} socket_instance_block_t;

// CQ stat info
typedef struct {
    uint64_t n_rx_stride_count;
    uint64_t n_rx_packet_count;
    uint64_t n_rx_consumed_rwqe_count;
    uint64_t n_rx_pkt_drop;
    uint64_t n_rx_lro_packets;
    uint64_t n_rx_lro_bytes;
    uint32_t n_rx_sw_queue_len;
    uint32_t n_rx_drained_at_once_max;
    uint32_t n_buffer_pool_len;
    uint16_t n_rx_max_stirde_per_packet;
} cq_stats_t;

typedef struct {
    bool b_enabled;
    cq_stats_t cq_stats;
} cq_instance_block_t;

typedef enum { RING_ETH = 0, RING_TAP } ring_type_t;

static const char *const ring_type_str[] = {"RING_ETH", "RING_TAP"};

// Ring stat info
typedef struct {
    uint64_t n_rx_pkt_count;
    uint64_t n_rx_byte_count;
    uint64_t n_tx_pkt_count;
    uint64_t n_tx_byte_count;
    uint64_t n_tx_retransmits;
    void *p_ring_master;
#ifdef DEFINED_UTLS
    uint32_t n_tx_tls_contexts;
    uint32_t n_rx_tls_contexts;
#endif /* DEFINED_UTLS */
    ring_type_t n_type;
    union {
        struct {
            uint64_t n_rx_interrupt_requests;
            uint64_t n_rx_interrupt_received;
            uint32_t n_rx_cq_moderation_count;
            uint32_t n_rx_cq_moderation_period;
            uint64_t n_tx_dropped_wqes;
            uint64_t n_tx_dev_mem_pkt_count;
            uint64_t n_tx_dev_mem_byte_count;
            uint64_t n_tx_dev_mem_oob;
            uint32_t n_tx_dev_mem_allocated;
        } simple;
        struct {
            char s_tap_name[IFNAMSIZ];
            uint32_t n_tap_fd;
            uint32_t n_rx_buffers;
            uint32_t n_vf_plugouts;
        } tap;
    };
} ring_stats_t;

typedef struct {
    bool b_enabled;
    ring_stats_t ring_stats;
} ring_instance_block_t;

// Buffer Pool stat info
typedef struct {
    bool is_rx;
    bool is_tx;
    uint32_t n_buffer_pool_size;
    uint32_t n_buffer_pool_no_bufs;
    uint32_t n_buffer_pool_expands;
} bpool_stats_t;

typedef struct {
    bool b_enabled;
    bpool_stats_t bpool_stats;
} bpool_instance_block_t;

// Version info
typedef struct {
    uint8_t vma_lib_maj;
    uint8_t vma_lib_min;
    uint8_t vma_lib_rev;
    uint8_t vma_lib_rel;
} version_info_t;

typedef struct sh_mem_t {
    int reader_counter; // only copy to shm upon active reader
    version_info_t ver_info;
    char stats_protocol_ver[32];
    vlog_levels_t log_level;
    uint8_t log_details_level;
    int fd_dump;
    vlog_levels_t fd_dump_log_level;
    cq_instance_block_t cq_inst_arr[NUM_OF_SUPPORTED_CQS];
    ring_instance_block_t ring_inst_arr[NUM_OF_SUPPORTED_RINGS];
    bpool_instance_block_t bpool_inst_arr[NUM_OF_SUPPORTED_BPOOLS];
    mc_grp_info_t mc_info;
    iomux_stats_t iomux;
    size_t max_skt_inst_num; // number of elements allocated in 'socket_instance_block_t
                             // skt_inst_arr[]'

    /* IMPORTANT:  MUST BE LAST ENTRY in struct: [0] is the allocation start point for all fd's
     *
     * Some compiler can report issue as 'array subscript is above array bounds'
     *
     * In ISO C90, you would have to give contents a length of 1,
     * which means either you waste space or complicate the argument to malloc.
     * Note:
     * - 1 was the portable way to go, though it was rather strange
     * - 0 was better at indicating intent, but not legal as far as
     * the Standard was concerned and supported as an extension by some compilers (including gcc)
     *
     * In ISO C99, you would use a flexible array member, which is slightly different in syntax and
     * semantics:
     * - Flexible array members are written as contents[] without the 0.
     * - Flexible array members have incomplete type, and so the sizeof operator may not be applied.
     *   As a quirk of the original implementation of zero-length arrays, sizeof evaluates to zero.
     * - Flexible array members may only appear as the last member of a struct that is otherwise
     * non-empty.
     * - A structure containing a flexible array member, or a union containing such a structure
     * (possibly recursively), may not be a member of a structure or an element of an array.
     * (However, these uses are permitted by GCC as extensions.)
     */
    socket_instance_block_t skt_inst_arr[1]; // sockets statistics array

    void reset()
    {
        reader_counter = 0;
        memset(&ver_info, 0, sizeof(ver_info));
        memset(stats_protocol_ver, 0, sizeof(stats_protocol_ver));
        max_skt_inst_num = 0;
        log_level = (vlog_levels_t)0;
        log_details_level = 0;
        fd_dump = 0;
        fd_dump_log_level = (vlog_levels_t)0;
        memset(cq_inst_arr, 0, sizeof(cq_inst_arr));
        memset(ring_inst_arr, 0, sizeof(ring_inst_arr));
        memset(bpool_inst_arr, 0, sizeof(bpool_inst_arr));
        memset(&mc_info, 0, sizeof(mc_info));
        memset(&iomux, 0, sizeof(iomux));
        for (uint32_t i = 0; i < max_skt_inst_num; i++) {
            skt_inst_arr[i].reset();
        }
    }
} sh_mem_t;

typedef struct sh_mem_info {
    char filename_sh_stats[PATH_MAX];
    size_t shmem_size;
    int fd_sh_stats;
    void *p_sh_stats;
    int pid;
} sh_mem_info_t;

// publisher functions
void vma_shmem_stats_open(vlog_levels_t **p_p_vma_log_level, uint8_t **p_p_vma_log_details);
void vma_shmem_stats_close();

void vma_stats_instance_create_socket_block(socket_stats_t *);
void vma_stats_instance_remove_socket_block(socket_stats_t *);

void vma_stats_mc_group_add(in_addr_t mc_grp, socket_stats_t *p_socket_stats);
void vma_stats_mc_group_remove(in_addr_t mc_grp, socket_stats_t *p_socket_stats);

void vma_stats_instance_create_ring_block(ring_stats_t *);
void vma_stats_instance_remove_ring_block(ring_stats_t *);

void vma_stats_instance_create_cq_block(cq_stats_t *);
void vma_stats_instance_remove_cq_block(cq_stats_t *);

void vma_stats_instance_create_bpool_block(bpool_stats_t *);
void vma_stats_instance_remove_bpool_block(bpool_stats_t *);

void vma_stats_instance_get_poll_block(iomux_func_stats_t *);
void vma_stats_instance_get_select_block(iomux_func_stats_t *);

void vma_stats_instance_create_epoll_block(int, iomux_func_stats_t *);
void vma_stats_instance_remove_epoll_block(iomux_func_stats_t *ep_stats);

// reader functions
void print_full_stats(socket_stats_t *p_si_stats, mc_grp_info_t *p_mc_grp_info, FILE *filename);
void print_netstat_like(socket_stats_t *p_si_stats, mc_grp_info_t *p_mc_grp_info, FILE *file,
                        int pid);
void print_netstat_like_headers(FILE *file);

#endif // VMA_STATS_H
