//
// Created by eugene on 3/14/19.
// Modified by ssrlive
//

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/certs.h>
#include <assert.h>
#include <stdbool.h>
#include "uv-mbed/uv-mbed.h"
#include "bio.h"

struct uv_mbed_s {
    uv_tcp_t socket;
    void *user_data;

    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    bool connected;

    uv_mbed_connect_cb connect_cb;
    void *connect_cb_p;

    uv_mbed_alloc_cb alloc_cb;
    uv_mbed_read_cb read_cb;
    void *read_cb_p;

    uv_mbed_close_cb close_cb;
    void *close_cb_p;

    struct bio *ssl_in;
    struct bio *ssl_out;
};

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *) ((char *) (ptr) - offsetof(type, member)))
#endif /* container_of */

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str);
static void _init_ssl(uv_mbed_t *mbed, const char *host_name, int dump_level);
static void _uv_dns_resolve_done_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

static void _uv_tcp_connect_established_cb(uv_connect_t* req, int status);
static void _uv_tcp_shutdown_cb(uv_shutdown_t* req, int status) ;

static bool mbed_ssl_process_in(uv_mbed_t *mbed);

struct uv_tcp_write_ctx {
    uint8_t *buf;
    uv_mbed_write_cb cb;
    void *cb_p;
};

static void mbed_ssl_process_out(uv_mbed_t *mbed, uv_mbed_write_cb cb, void *p);
static int _mbed_ssl_recv(void* ctx, uint8_t *buf, size_t len);
static int _mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len);

static void mbed_continue_handshake(uv_mbed_t *mbed);

uv_mbed_t * uv_mbed_init(uv_loop_t *loop, const char *host_name, void *user_data, int dump_level) {
    uv_mbed_t *mbed = (uv_mbed_t *) calloc(1, sizeof(*mbed));
    mbed->user_data = user_data;
    uv_tcp_init(loop, &mbed->socket);
    _init_ssl(mbed, host_name, dump_level);
    return mbed;
}

void * uv_mbed_user_data(uv_mbed_t *mbed) {
    return mbed->user_data;
}

static int _uv_stream_fd(const uv_tcp_t *handle) {
#if defined(_WIN32)
    return handle->socket;
#elif defined(__APPLE__)
    int uv___stream_fd(const uv_stream_t* handle);
    return uv___stream_fd((const uv_stream_t *)handle);
#else
    return (handle)->io_watcher.fd;
#endif
}

int uv_mbed_get_stream_fd(const uv_mbed_t *mbed) {
    return mbed ? _uv_stream_fd(&mbed->socket) : -1; /* (~0) */
}

static void _close_ssl_process_cb(uv_mbed_t *mbed, int status, void *p) {
    uv_shutdown_t *sr = (uv_shutdown_t *)calloc(1, sizeof(uv_shutdown_t));
    sr->data = mbed;
    uv_shutdown(sr, (uv_stream_t *) &mbed->socket, _uv_tcp_shutdown_cb);
}

int uv_mbed_close(uv_mbed_t *mbed, uv_mbed_close_cb close_cb, void *p) {
    int rc;
    assert(mbed && close_cb);
    mbed->close_cb = close_cb;
    mbed->close_cb_p = p;
    rc = mbedtls_ssl_close_notify(&mbed->ssl);

    if (mbed->connected == false) {
        close_cb(mbed, p);
        return 0;
    }

    uv_read_stop((uv_stream_t*)&mbed->socket);

    mbed_ssl_process_out(mbed, &_close_ssl_process_cb, p);
    return 0;
}

int uv_mbed_connect(uv_mbed_t *mbed, const char *remote_addr, int port, uv_mbed_connect_cb cb, void *p) {
    char portstr[6] = { 0 };
    uv_loop_t *loop = mbed->socket.loop;
    uv_getaddrinfo_t *req = (uv_getaddrinfo_t *)calloc(1, sizeof(*req));

    mbed->connect_cb = cb;
    mbed->connect_cb_p = p;

    req->data = mbed;
    sprintf(portstr, "%d", port);
    return uv_getaddrinfo(loop, req, _uv_dns_resolve_done_cb, remote_addr, portstr, NULL);
}

int uv_mbed_set_blocking(uv_mbed_t *um, int blocking) {
    return uv_stream_set_blocking((uv_stream_t *) &um->socket, blocking);
}

void uv_mbed_set_read_callback(uv_mbed_t *mbed, uv_mbed_alloc_cb alloc_cb, uv_mbed_read_cb read_cb, void *p) {
    mbed->alloc_cb = alloc_cb;
    mbed->read_cb = read_cb;
    mbed->read_cb_p = p;
}

int uv_mbed_write(uv_mbed_t *mbed, const uv_buf_t *buf, uv_mbed_write_cb cb, void *p) {
    int rc = 0;
    int sent = 0;

    while (sent < (int) buf->len) {
        unsigned char *data = (unsigned char *)(buf->base + (size_t)sent);
        rc = mbedtls_ssl_write(&mbed->ssl, data, buf->len - (size_t)sent);

        if (rc >= 0) {
            sent += rc;
        }

        if (rc < 0) {
            break;
        }
    }

    if (sent > 0) {
        mbed_ssl_process_out(mbed, cb, p);
        rc = 0;
    }
    else {
        cb(mbed, rc, p);
    }
    return rc;
}

static void _init_ssl(uv_mbed_t *mbed, const char *host_name, int dump_level) {
    uint64_t seed[2];

    mbedtls_debug_set_threshold(dump_level); // DEBUG_LEVEL

    mbedtls_ssl_init(&mbed->ssl);
    mbedtls_ssl_config_init(&mbed->conf);
    mbedtls_x509_crt_init(&mbed->cacert);
    mbedtls_ctr_drbg_init(&mbed->ctr_drbg);

    mbedtls_entropy_init(&mbed->entropy);

    seed[0] = uv_hrtime(); seed[1] = uv_hrtime();
    mbedtls_ctr_drbg_seed(&mbed->ctr_drbg, mbedtls_entropy_func, &mbed->entropy,
        (uint8_t *)seed, sizeof(seed));

    mbedtls_x509_crt_parse( &mbed->cacert, (const unsigned char *) mbedtls_test_cas_pem,
        mbedtls_test_cas_pem_len );

    mbedtls_ssl_config_defaults(&mbed->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT );

    /* OPTIONAL is not optimal for security, but makes interop easier in this stage */
    mbedtls_ssl_conf_authmode(&mbed->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&mbed->conf, &mbed->cacert, NULL );
    mbedtls_ssl_conf_rng(&mbed->conf, mbedtls_ctr_drbg_random, &mbed->ctr_drbg);
    mbedtls_ssl_conf_dbg(&mbed->conf, tls_debug_f, stdout);

    mbedtls_ssl_setup(&mbed->ssl, &mbed->conf);

    mbedtls_ssl_set_hostname(&mbed->ssl, host_name);

    mbed->ssl_in = bio_new(true);
    mbed->ssl_out = bio_new(false);
    mbedtls_ssl_set_bio(&mbed->ssl, mbed, _mbed_ssl_send, _mbed_ssl_recv, NULL);
}

int uv_mbed_free(uv_mbed_t *mbed) {
    mbedtls_ctr_drbg_context *rng;
    mbedtls_entropy_context *ctx;
    bio_free(mbed->ssl_in);
    bio_free(mbed->ssl_out);
    mbedtls_ssl_free(&mbed->ssl);

    rng = (mbedtls_ctr_drbg_context *) mbed->conf.p_rng;
    ctx = (mbedtls_entropy_context *)rng->p_entropy;
    mbedtls_entropy_free(ctx);
    assert(ctx == &mbed->entropy);
    mbedtls_ctr_drbg_free(rng);
    assert(rng == &mbed->ctr_drbg);

    mbedtls_ssl_config_free(&mbed->conf);

    mbedtls_x509_crt_free(&mbed->cacert);

    free(mbed);

    return 0;
}

static void tls_debug_f(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    printf("%s:%04d: %s", file, line, str );
    fflush(  stdout );
}

static void _uv_tcp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *base = (char*) calloc(suggested_size, sizeof(*base));
    *buf = uv_buf_init(base, (unsigned int)suggested_size);
}

static bool _do_uv_mbeb_connect_cb(uv_mbed_t *mbed, int status) {
    bool result = false;
    if (mbed && mbed->connect_cb) {
        mbed->connect_cb(mbed, status, mbed->connect_cb_p);
        mbed->connect_cb = NULL;
        mbed->connect_cb_p = NULL;
        result = true;
    }
#if 0
    if (status == 0) {
        uint32_t flags = mbedtls_ssl_get_verify_result( &mbed->ssl );
        if (flags != 0) {
            char vrfy_buf[512] = { 0 };
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            printf("%s\n", vrfy_buf);
        }
    }
#endif
    return result;
}

static void _uv_dns_resolve_done_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    uv_mbed_t *mbed = (uv_mbed_t *) req->data;

    if (status < 0) {
        _do_uv_mbeb_connect_cb(mbed, status);
    }
    else {
        uv_connect_t *tcp_cr = (uv_connect_t *) calloc(1, sizeof(uv_connect_t));
        tcp_cr->data = mbed;
        uv_tcp_connect(tcp_cr, &mbed->socket, res->ai_addr, _uv_tcp_connect_established_cb);
    }
    uv_freeaddrinfo(res);
    free(req);
}

static void _uv_tcp_read_done_cb (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    uv_mbed_t *mbed = (uv_mbed_t *) stream->data;
    bool release_buf = true;
    assert(stream == (uv_stream_t *) &mbed->socket);
    if (nread > 0) {
        struct bio *in = mbed->ssl_in;
        bool rc = bio_put(in, (uint8_t *)buf->base, (size_t) nread);
        while (bio_available(in)) {
            if (mbed_ssl_process_in(mbed) == false) {
                break;
            }
        }
        if (bio_is_zero_copy(in) && rc) {
            release_buf = false;
        }
    }

    if (release_buf) {
        free((void *)buf->base);
    }

    if (nread < 0) {
        if (_do_uv_mbeb_connect_cb(mbed, (int)nread)) {
            return;
        }
        else if (mbed->read_cb) {
            uv_buf_t b = uv_buf_init(NULL, 0);
            mbed->read_cb(mbed, nread, &b, mbed->read_cb_p);
        }
    }
}

static void _uv_tcp_connect_established_cb(uv_connect_t *req, int status) {
    uv_mbed_t *mbed = (uv_mbed_t *) req->data;
    // uv_mbed_t *mbed = container_of((uv_tcp_t*)req->handle, uv_mbed_t, socket);
    if (status < 0) {
        _do_uv_mbeb_connect_cb(mbed, status);
    }
    else {
        //uv_stream_t* socket = req->handle;
        uv_stream_t *socket = (uv_stream_t*)&mbed->socket;
        socket->data = mbed;
        mbed->connected = true;
        uv_read_start(socket, _uv_tcp_alloc_cb, _uv_tcp_read_done_cb);
        mbed_ssl_process_in(mbed);
    }
    free(req);
}

static void _uv_tcp_close_done_cb (uv_handle_t *h) {
    uv_mbed_t *mbed = container_of((uv_tcp_t*)h, uv_mbed_t, socket);
    assert(mbed);
    if (mbed->close_cb) {
        mbed->close_cb(mbed, mbed->close_cb_p);
    }
}

static void _uv_tcp_shutdown_cb(uv_shutdown_t* req, int status) {
    uv_mbed_t *mbed = (uv_mbed_t *) req->data;
    assert(req->handle == (uv_stream_t *)&mbed->socket);
    uv_close((uv_handle_t *) &mbed->socket, _uv_tcp_close_done_cb);
    free(req);
}

static void _uv_mbed_tcp_write_done_cb(uv_write_t *req, int status) {
    struct uv_tcp_write_ctx *ctx = (struct uv_tcp_write_ctx *) req->data;
    uv_mbed_t *mbed = container_of((uv_tcp_t*)req->handle, uv_mbed_t, socket);

    assert(mbed);
    assert(ctx);
    assert(ctx->cb);

    ctx->cb(mbed, status, ctx->cb_p);

    free(ctx->buf);
    free(ctx);
    free(req);
}

static int _mbed_ssl_recv(void* ctx, uint8_t *buf, size_t len) {
    uv_mbed_t *mbed = (uv_mbed_t *) ctx;
    struct bio *in = mbed->ssl_in;
    if (bio_available(in) == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return (int) bio_read(in, buf, len);
}

static int _mbed_ssl_send(void* ctx, const uint8_t *buf, size_t len) {
    uv_mbed_t *mbed = (uv_mbed_t *) ctx;
    struct bio *out = mbed->ssl_out;
    bio_put(out, buf, len);
    return (int) len;
}

static void _mbed_handshake_write_cb(uv_mbed_t *mbed, int status, void *p) {
    if (status != MBEDTLS_ERR_SSL_WANT_WRITE) {
        mbed_continue_handshake(mbed);
    }
}

static bool mbed_ssl_process_in(uv_mbed_t *mbed) {
#define UV_MBED_RCV_LEN (64 * 1024)
    bool to_continue = true;
    do {
        struct bio *in = mbed->ssl_in;
        ssize_t recv = 0;
        uv_buf_t buf = uv_buf_init(NULL, 0);

        if (mbed->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
            mbed_continue_handshake(mbed);
            break;
        }
        if (mbed->alloc_cb == NULL || mbed->read_cb == NULL) {
            to_continue = false;
            break;
        }
        if (bio_available(in) == 0) {
            break;
        }

        mbed->alloc_cb(mbed, UV_MBED_RCV_LEN, &buf);
        if (buf.base == NULL || buf.len == 0) {
            recv = UV_ENOBUFS;
        } else {
            while (bio_available(in) > 0 && (buf.len - (size_t)recv) > 0) {
                uint8_t *data = (uint8_t *) buf.base + (size_t)recv;
                size_t data_len = (size_t)buf.len - (size_t)recv;
                int read = mbedtls_ssl_read(&mbed->ssl, data, data_len);
                if (read < 0) {
                    break;
                }
                recv += (ssize_t)read;
            }
        }
        mbed->read_cb(mbed, recv, &buf, mbed->read_cb_p);
        to_continue = (recv >= 0);
    } while(0);
    return to_continue;
}

static void mbed_continue_handshake(uv_mbed_t *mbed) {
    int rc = mbedtls_ssl_handshake(&mbed->ssl);
    switch (rc) {
    case 0:
        _do_uv_mbeb_connect_cb(mbed, rc);
        break;
    case MBEDTLS_ERR_SSL_WANT_WRITE:
    case MBEDTLS_ERR_SSL_WANT_READ:
        mbed_ssl_process_out(mbed, &_mbed_handshake_write_cb, NULL);
        break;
    default:
        (void)mbed;
    }
}

static void mbed_ssl_process_out(uv_mbed_t *mbed, uv_mbed_write_cb cb, void *p) {
    struct bio *out = mbed->ssl_out;
    size_t avail = bio_available(out);

    if (avail == 0) {
        // how did we get here?
        cb(mbed, MBEDTLS_ERR_SSL_WANT_WRITE, p);
    } else {
        size_t len;
        uv_write_t *tcp_wr;
        uv_buf_t wb;
        struct uv_tcp_write_ctx *ctx;

        ctx = (struct uv_tcp_write_ctx *) calloc(1, sizeof(*ctx));
        ctx->buf = (uint8_t *)calloc(avail, sizeof(uint8_t));
        ctx->cb = cb;
        ctx->cb_p = p;

        len = bio_read(out, ctx->buf, avail);

        tcp_wr = (uv_write_t *) calloc(1, sizeof(uv_write_t));
        tcp_wr->data = ctx;
        wb = uv_buf_init((char *) ctx->buf, (unsigned int) len);
        uv_write(tcp_wr, (uv_stream_t *) &mbed->socket, &wb, 1, _uv_mbed_tcp_write_done_cb);
        assert((avail = bio_available(out)) == 0);
    }
}

