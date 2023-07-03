/* gcc -I./install/include example.c -o example -libverbs */

#include <mellanox/xlio_extra.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <infiniband/verbs.h>

struct express_sq {
    express_socket *sock;
};

struct xlio_api_t *g_xlio_api;

static bool connected = false;
static bool received = false;
static bool send_complete = false;

static struct {
    /* This is imitation of a PDU object which is reported in ZC completion. */
    int unused;
} pdu;

static void *express_alloc(size_t size, uint32_t *user_mkey)
{
    /*
     * Allocate and register memory. XLIO will register memory on its own.
     *
     * Note, hugepages allocator instead of malloc() is more efficient.
     */

    void *addr = malloc(size);
    *user_mkey = 1;

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
    printf("socket event: %d\n", event);
    connected = (event == EXPRESS_EVENT_ESTABLISHED);
}

static void express_rx_cb(void *opaque_sq, void *addr, size_t len, express_buf *buf)
{
    struct express_sq *sq = (struct express_sq *)opaque_sq;

    char s[128] = {};
    memcpy(s, addr, len);
    printf("received (mkey=%u): %s\n", buf->user_mkey, s);

    received = true;

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
    printf("ZC completeion callback\n");
    assert(opaque_op == &pdu);
    send_complete = true;
}

int main()
{
    struct express_sq sq;
    socklen_t len;
    int rc;
    static char header[] = "hello world\n";
    static char payload[4096];
    static char key[32];

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
    struct ibv_pd *pd = g_xlio_api->express_get_pd("mlx5_3");
    assert(pd != NULL);

    struct express_socket_attr attr;
    g_xlio_api->express_socket_attr_init(&attr);

    /* Example address is 127.0.0.1:8080 */
    attr.addr.addr_in.sin_family = AF_INET;
    attr.addr.addr_in.sin_port = htons(8080); // TCP port 8080
    rc = inet_aton("192.168.10.15", &attr.addr.addr_in.sin_addr); // IP 127.0.0.1
    assert(rc != 0);
    attr.addr_len = sizeof(attr.addr.addr_in);

    attr.event_cb = express_event_cb;
    attr.rx_cb = express_rx_cb;
    attr.zc_cb = express_zc_cb;
    attr.opaque_sq = (void *)&sq;
    attr.key = key;
    attr.keylen = 32;

    /* Important, socket is "bound" to current pthread/CPU core. */
    express_socket *sock = sq.sock = g_xlio_api->express_socket_create(&attr);
    if (sock == NULL) {
        printf("Failed to create TCP connection (errno=%d)\n", errno);
        return 1;
    }

    while (!connected) {
        g_xlio_api->express_poll();
    }

    /* Memory registration in the XLIO protection domain. */
    struct ibv_mr *mr_header = ibv_reg_mr(pd, header, sizeof(header),
                                          IBV_ACCESS_LOCAL_WRITE);
    assert(mr_header != NULL);
    struct ibv_mr *mr_payload = ibv_reg_mr(pd, payload, sizeof(payload),
                                           IBV_ACCESS_LOCAL_WRITE);
    assert(mr_payload != NULL);
    uint32_t mkey_header = mr_header->lkey;
    uint32_t mkey_payload = mr_payload->lkey;

    /*
     * MSG_MORE flag doesn't trigger sending to wire and allows to batch with
     * the next send operation.
     *
     * 'pdu' pointer will be provided to zc_cb once TCP layer finishes using
     * the buffer. NULL opaque values don't generate a ZC completion, so opaque
     * can be set in the last chunk of a PDU and the completion callback will
     * indicate full PDU completion.
     */
    memset(payload, 'a', sizeof(payload));
    rc = g_xlio_api->express_send(sock, header, sizeof(header), mkey_header, MSG_MORE, NULL)
      ?: g_xlio_api->express_send(sock, payload, sizeof(payload), mkey_payload, EXPRESS_SEND_FLAG_CRYPTO, &pdu);

    /* express_send() doesn't support partial send. It either queues all data or fails. */
    assert(rc == 0);

    while (!(received && send_complete)) {
        g_xlio_api->express_poll();
    }

    g_xlio_api->express_socket_terminate(sock);

    sleep(1);

/*
    while (connected) {
        g_xlio_api->express_poll();
    }
*/

    /* Cleanup. */
    ibv_dereg_mr(mr_header);
    ibv_dereg_mr(mr_payload);

    return 0;
}
