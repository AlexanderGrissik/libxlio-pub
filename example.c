
#include <mellanox/xlio_extra.h>

struct express_sq {
    express_socket *sock;
};

struct xlio_api_t *g_xlio_api;

static bool connected = false;
static bool received = false;
static bool send_complete = false;

static void *express_alloc(size_t size, uint32_t *user_mkey)
{
    /*
     * Allocate and register memory. XLIO will register memory on its own
     * and user_mkey is for application purpose only (e.g. RDMA operation).
     *
     * user_mkey will be provided to rx_cb().
     *
     * Note, hugepages allocator instead of malloc() is more efficient.
     */

    void *addr = malloc(size);
    struct ibv_mr *mr = ibv_reg_mr(xlio_pd, addr, size, access);

    *user_mkey = mr->lkey;
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

static express_event_cb(void *opaque_sq, enum express_event_t event)
{
    connected = (event == EXPRESS_EVENT_ESTABLISHED);
}

static express_rx_cb(void *opaque_sq, void *addr, size_t len, uint32_t user_mkey, express_buf *buf)
{
    struct express_sq *sq = (struct express_sq *)opaque_sq;

    recevied = true;

    /*
     * Arm RDMA operation to host.
     * 'addr' is within previously allocated memory area, so it can be
     * registered in advance.
     *
     * After RMDA operation is completed, free the buffer:
     */
    g_xlio_api->express_free_rx_buf(sq->sock, buf);
}

static express_zc_cb(void *opaque_sq, void *opaque_op)
{
    send_complete = true;
}

int main()
{
    struct express_sq sq;
    socklen_t len;
    int rc;
    char buf[] = "hello world";

    len = sizeof(g_xlio_api);
    rc = getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API, &g_xlio_api, &len);
    if (rc != 0 || g_xlio_api == NULL) {
        printf("Failed to get XLIO API\n");
        return 1;
    }

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
    struct ibv_pd *pd = g_xlio_api->express_get_pd("mlx5_1");

    struct express_socket_attr attr;
    g_xlio_api->express_socket_attr_init(&attr);

    /* Example address is 127.0.0.1:8080 */
    attr.addr.addr_in.sin_family = AF_INET;
    attr.addr.addr_in.sin_port = htons(8080); // TCP port 8080
    rc = inet_aton("127.0.0.1", &attr.addr.addr_in.sin_addr); // IP 127.0.0.1
    assert(rc != 0);
    attr.addr.addr_len = sizeof(attr.addr.addr_in);

    attr.event_cb = express_event_cb;
    attr.rx_cb = express_rx_cb;
    attr.zc_cb = express_zc_cb;
    attr.opaque_sq = (void *)&sq;

    /* Important, socket is "bound" to current pthread/CPU core. */
    express_socket *sock = sq.sock = g_xlio_api->express_socket_create(&attr);
    if (sock == NULL) {
        printf("Failed to create TCP connection (errno=%d)\n", errno);
        return 1;
    }

    while (!connected) {
        g_xlio_api->express_poll();
    }

    /*
     * MSG_MORE flag doesn't trigger sending to wire and allows to batch with
     * the next send operation.
     * 'pdu' pointer will be provided to zc_cb once TCP layer.
     */
    rc = g_xlio_api->express_send(sock, buf_hdr, sizeof(buf_hdr), mkey, MSG_MORE, NULL)
      ?: g_xlio_api->express_send(sock, buf_payload, sizeof(buf_payload), mkey, 0, pdu);

    /* express_send() doesn't support partial send. It either queues all data or fails. */
    assert(rc == 0);


    while (!(received && send_complete)) {
        g_xlio_api->express_poll();
    }

    g_xlio_api->express_socket_terminate(sock);

    while (connected) {
        g_xlio_api->express_poll();
    }

    return 0;
}
