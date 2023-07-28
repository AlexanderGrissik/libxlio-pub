/* gcc -pthread -I./install/include example-mt.c -o example-mt -libverbs -lpthread */

/* XLIO_PROGRESS_ENGINE_INTERVAL=0 XLIO_RING_ALLOCATION_LOGIC_TX=20 XLIO_RING_ALLOCATION_LOGIC_RX=20 LD_PRELOAD=libxlio.so ./example-mt */

#include <mellanox/xlio_extra.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <infiniband/verbs.h>

#define EXPRESS_THREADS_MAX 16
#define EXPRESS_THREADS 2

struct xlio_api_t *g_xlio_api;

static char header[] = "hello ";
static char payload[] = "world";
static uint32_t mkey_header;
static uint32_t mkey_payload;

static struct express_thread_t {
    pthread_t id;
    int tid;
} threads[EXPRESS_THREADS_MAX];

struct express_sq {
    express_socket *sock;
    struct express_thread_t *thread;
    bool connected;
    bool received;
    bool send_complete;
    bool quit;
};

static void *express_alloc(size_t size, uint32_t *user_mkey)
{
    /*
     * Allocate and register memory. XLIO will register memory on its own
     * and user_mkey is for application purpose only (e.g. RDMA operation).
     *
     * user_mkey will be provided to rx_cb() via buf->user_mkey.
     *
     * Note, hugepages allocator instead of malloc() is more efficient.
     */

    void *addr = malloc(size);

    /* Use can register memory and provide the mkey here. */
    *user_mkey = 0;

    return addr;
}

static void express_free(void *buf)
{
    /* XLIO frees memory in the library destructor. */
    free(buf);
}

/* Copy-paste from SPDK */
static int xlio_allocator_init()
{
    int rc;
#pragma pack(push, 1)
    struct {
        uint8_t flags;
        void *(*alloc_func)(size_t, uint32_t *);
        void (*free_func)(void *);
    } data;
#pragma pack(pop)
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(sizeof(data))];

    /* XLIO reads data by advancing pointer instead of using a struct... */
    static_assert((sizeof(uint8_t) + sizeof(uintptr_t) +
                sizeof(uintptr_t)) == sizeof(data),
            "wrong xlio ioctl data size.");

    /* XLIO doesn't export allocator API... */
    enum {
        IOCTL_USER_ALLOC_RX = (1 << 1),
        IOCTL_USER_ALLOC_RX_MKEY = (1 << 4),
    };

    cmsg = (struct cmsghdr *)cbuf;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = CMSG_XLIO_IOCTL_USER_ALLOC;
    cmsg->cmsg_len = CMSG_LEN(sizeof(data));
    /* Only RX buffer pool will be allocated with user allocator. */
    data.flags = IOCTL_USER_ALLOC_RX | IOCTL_USER_ALLOC_RX_MKEY;
    data.alloc_func = express_alloc;
    data.free_func = express_free;
    memcpy(CMSG_DATA(cmsg), &data, sizeof(data));

    rc = g_xlio_api->ioctl(cmsg, cmsg->cmsg_len);
    if (rc < 0) {
        printf("Failed to register XLIO allocator (rc=%d errno=%d)\n", rc, errno);
    }
    return rc;
}

static void express_event_cb(void *opaque_sq, enum express_event_t event)
{
    struct express_sq *sq = (struct express_sq *)opaque_sq;

    printf("tid#%d: event %d callback\n", sq->thread->tid, event);
    assert(sq->sock != NULL);
    sq->connected = (event == EXPRESS_EVENT_ESTABLISHED);
}

static void express_rx_cb(void *opaque_sq, void *addr, size_t len, express_buf *buf)
{
    struct express_sq *sq = (struct express_sq *)opaque_sq;

    printf("tid#%d: rx callback\n", sq->thread->tid);
    sq->received = true;

    char s[128] = {};
    memcpy(s, addr, len);
    printf("tid#%d: received %s\n", sq->thread->tid, s);
    if (strncmp("exit", s, 4) == 0) {
        sq->quit = true;
    }

    /*
     * Arm RDMA operation to host.
     * 'addr' is within previously allocated memory area, so it can be
     * registered in advance.
     *
     * After RMDA operation is completed, free the buffer:
     */
    g_xlio_api->express_free_rx_buf(sq->sock, buf);
}

static void express_zc_cb(void *opaque_sq, void *opaque_op)
{
    struct express_sq *sq = (struct express_sq *)opaque_sq;

    printf("tid#%d: zc callback\n", sq->thread->tid);
    assert(opaque_op == sq->thread);
    sq->send_complete = true;
}

static void *thread_loop(void *arg)
{
    struct express_thread_t *t = (struct express_thread_t *)arg;
    struct express_sq sq = {};
    int rc;

    printf("Thread #%d started\n", t->tid);

    struct express_socket_attr attr;
    g_xlio_api->express_socket_attr_init(&attr);

    attr.addr.addr_in.sin_family = AF_INET;
    attr.addr.addr_in.sin_port = htons(8080 + t->tid);
    rc = inet_aton("11.210.12.2", &attr.addr.addr_in.sin_addr);
    assert(rc != 0);
    attr.addr_len = sizeof(attr.addr.addr_in);

    attr.event_cb = express_event_cb;
    attr.rx_cb = express_rx_cb;
    attr.zc_cb = express_zc_cb;
    attr.opaque_sq = &sq;

    sq.thread = t;

    /* Important, socket is "bound" to current pthread/CPU core. */
    express_socket *sock = sq.sock = g_xlio_api->express_socket_create(&attr);
    if (sock == NULL) {
        printf("Failed to create TCP connection (errno=%d)\n", errno);
        return NULL;
    }

    while (!sq.connected) {
        g_xlio_api->express_poll();
    }

    /*
     * MSG_MORE flag doesn't trigger sending to wire and allows to batch with
     * the next send operation.
     *
     * 'pdu' pointer will be provided to zc_cb once TCP layer finishes using
     * the buffer. NULL opaque values don't generate a ZC completion, so opaque
     * can be set in the last chunk of a PDU and the completion callback will
     * indicate full PDU completion.
     */
    rc = g_xlio_api->express_send(sock, header, sizeof(header), mkey_header, MSG_MORE, NULL)
      ?: g_xlio_api->express_send(sock, payload, sizeof(payload), mkey_payload, 0, t);

    /* express_send() doesn't support partial send. It either queues all data or fails. */
    assert(rc == 0);

    while (!(sq.received && sq.send_complete && sq.quit)) {
        g_xlio_api->express_poll();
    }

    printf("tid#%d: terminating...\n", t->tid);
    g_xlio_api->express_socket_terminate(sock);

    while (sq.connected) {
        g_xlio_api->express_poll();
    }

    return NULL;
}

int main()
{
    struct express_sq sq;
    socklen_t len;
    int rc;

    /* Obtain XLIO extra API pointers. */
    len = sizeof(g_xlio_api);
    rc = getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API, &g_xlio_api, &len);
    if (rc != 0 || g_xlio_api == NULL) {
        printf("Failed to get XLIO API\n");
        return 1;
    }

    /* User allocator must be provided before any XLIO or socket API. */
    rc = xlio_allocator_init();
    if (rc != 0) {
        return 1;
    }

    /*
     * At this point we don't have any socket, so we need to understand what
     * outgoing ib device will be used.
     *
     * Send operation requires mkey within its protection domain.
     */
    struct ibv_pd *pd = g_xlio_api->express_get_pd("mlx5_4");
    assert(pd != NULL);

    /* Memory registration in the XLIO protection domain. */
    struct ibv_mr *mr_header = ibv_reg_mr(pd, header, sizeof(header),
                                          IBV_ACCESS_LOCAL_WRITE);
    assert(mr_header != NULL);
    struct ibv_mr *mr_payload = ibv_reg_mr(pd, payload, sizeof(payload),
                                           IBV_ACCESS_LOCAL_WRITE);
    assert(mr_payload != NULL);
    mkey_header = mr_header->lkey;
    mkey_payload = mr_payload->lkey;

    for (int i = 0; i < EXPRESS_THREADS; ++i) {
        threads[i].tid = i;
        rc = pthread_create(&threads[i].id, NULL, &thread_loop, &threads[i]);
        assert(rc == 0);
    }

    for (int i = 0; i < EXPRESS_THREADS; ++i) {
        pthread_join(threads[i].id, NULL);
    }

    /* Cleanup. */
    ibv_dereg_mr(mr_header);
    ibv_dereg_mr(mr_payload);

    return 0;
}
