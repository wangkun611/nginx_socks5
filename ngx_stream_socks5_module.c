#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_string.h>
#include <ngx_crypt.h>
#include "ngx_stream_socks5_module.h"

typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_stream_socks5_vars_t;

typedef struct {
    ngx_msec_t                       client_header_timeout;   /* read socks5 header timeout */
    ngx_flag_t                       socket_keepalive;
    ngx_msec_t                       timeout;
    ngx_flag_t                       next_upstream;
    ngx_uint_t                       next_upstream_tries;
    ngx_msec_t                       next_upstream_timeout;
    ngx_msec_t                       connect_timeout;
    size_t                           buffer_size;
    ngx_stream_complex_value_t      *upload_rate;
    ngx_stream_complex_value_t      *download_rate;

    ngx_stream_socks5_vars_t         vars;


    ngx_int_t                        auth;
    ngx_stream_complex_value_t       user_file;
    ngx_int_t                        upstream_protocol; /* 0 none 1 socks5 2 http 3 trojan 4 websocket */

#if (NGX_STREAM_SSL)
    ngx_flag_t                       ssl_enable;
    ngx_flag_t                       ssl_session_reuse;
    ngx_uint_t                       ssl_protocols;
    ngx_str_t                        ssl_ciphers;
    ngx_stream_complex_value_t      *ssl_name;
    ngx_flag_t                       ssl_server_name;

    ngx_flag_t                       ssl_verify;
    ngx_uint_t                       ssl_verify_depth;
    ngx_str_t                        ssl_trusted_certificate;
    ngx_str_t                        ssl_crl;
    ngx_str_t                        ssl_certificate;
    ngx_str_t                        ssl_certificate_key;
    ngx_array_t                     *ssl_passwords;

    ngx_ssl_t                       *ssl;
#endif

    ngx_stream_upstream_srv_conf_t  *upstream;
    ngx_stream_complex_value_t      *upstream_value;

    ngx_str_t                        upstream_username;
    ngx_str_t                        upstream_password;
} ngx_stream_socks5_srv_conf_t;

typedef struct {
    ngx_buf_t                 downstream_buf;
    ngx_stream_filter_pt      dwonstream_writer;
    ngx_stream_filter_pt      upstream_writer;
    /* 0: read downstream version identifier/method selection message
     * 1: read username/password
     * 2: read downstream Requests details
     * 3: connecting upstream
     * 4: connected
     */
    ngx_int_t                  downstream_phase;
    ngx_str_t                 *username;
    ngx_str_t                 *password;
    ngx_int_t                  cmd;
    ngx_addr_t                 dst_addr;
    ngx_int_t                  dst_port;

    ngx_stream_socks5_vars_t   vars;

    ngx_int_t                  upstream_protocol; /* 0 none 1 socks5 2 http 3 trojan 4 websocket */

#if (NGX_STREAM_SSL)
    ngx_flag_t                 ssl_enable;
#endif

    ngx_int_t                (*send_request)(ngx_stream_session_t *r);
    ngx_int_t                (*resend_request)(ngx_stream_session_t *r);
    ngx_int_t                (*process_header)(ngx_stream_session_t *r);
} ngx_stream_socks5_ctx_t;

static void ngx_stream_socks5_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_socks5_eval(ngx_stream_session_t *s,
    ngx_stream_socks5_ctx_t *ctx, ngx_stream_socks5_srv_conf_t *pscf);
static void ngx_stream_socks5_connect(ngx_stream_session_t *s);
static void ngx_stream_socks5_init_upstream(ngx_stream_session_t *s);
static void ngx_stream_socks5_upstream_send_request(ngx_stream_session_t *s,
    ngx_uint_t do_write);

static void
ngx_stream_socks5_process_header_handler(ngx_event_t *ev);
/*
 * 处理upstream的消息头
 */
static void ngx_stream_socks5_process_header(ngx_stream_session_t *s);
/*
 * 与upstream协议协商成功，向downstream发送成功消息。
 */
static void ngx_stream_socks5_send_response(ngx_stream_session_t *s);

static void ngx_stream_socks5_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_stream_socks5_process_reqeust(ngx_event_t *ev);
static ngx_int_t ngx_stream_socks5_process_reqeust_first(ngx_stream_session_t *s,
    ngx_buf_t *b);
static ngx_int_t ngx_stream_socks5_process_reqeust_details(ngx_stream_session_t *s,
    ngx_buf_t *b);

static void ngx_stream_socks5_process_connect(ngx_stream_session_t *s);
/*
static void ngx_stream_socks5_process_bind(ngx_stream_session_t *s);
static void ngx_stream_socks5_process_udp(ngx_stream_session_t *s);
*/

static void ngx_stream_socks5_downstream_handler(ngx_event_t *ev);
static void ngx_stream_socks5_upstream_handler(ngx_event_t *ev);
static void ngx_stream_socks5_process_connection(ngx_event_t *ev,
    ngx_uint_t from_upstream);
static void ngx_stream_socks5_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_socks5_test_connect(ngx_connection_t *c);
/*
 * 尝试从downstream读取数据
 * 返回值
 *  >0  缓冲区字节数大小
 *  =0  通道已经关闭
 *  <0  错误,需要区分NGX_AGAIN
 */
static ssize_t ngx_stream_socks5_read_request(ngx_stream_session_t *s,
    ngx_stream_socks5_ctx_t *ctx);
static void ngx_stream_socks5_process(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_uint_t do_write);
static ngx_int_t ngx_stream_socks5_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream);
static void ngx_stream_socks5_dummy_handler(ngx_event_t *ev);
static void ngx_stream_socks5_next_upstream(ngx_stream_session_t *s);
static void ngx_stream_socks5_finalize(ngx_stream_session_t *s, ngx_uint_t rc);
static u_char *ngx_stream_socks5_log_error(ngx_log_t *log, u_char *buf, size_t len);

static void *ngx_stream_socks5_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_socks5_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_socks5_set_ssl(ngx_conf_t *cf,
    ngx_stream_socks5_srv_conf_t *sscf);

ngx_stream_socks5_ctx_t *ngx_http_socks5_create_ctx(ngx_stream_session_t *s);
static char *ngx_stream_socks5_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_socks5_auth_basic_user_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_stream_socks5_set_vars(ngx_url_t *u, ngx_stream_socks5_vars_t *v);

static ngx_int_t ngx_stream_socks5_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_stream_socks5_dst_addr_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_socks5_dst_port_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

#if (NGX_STREAM_SSL)
static char *ngx_stream_socks5_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_stream_socks5_ssl_init_connection(ngx_stream_session_t *s);
static void ngx_stream_socks5_ssl_handshake(ngx_connection_t *pc);
static void ngx_stream_socks5_ssl_save_session(ngx_connection_t *c);
static ngx_int_t ngx_stream_socks5_ssl_name(ngx_stream_session_t *s);

/* trojan */
static ngx_int_t ngx_stream_socks5_trojan_send_request(ngx_stream_session_t *r);
static ngx_int_t ngx_stream_socks5_trojan_resend_request(ngx_stream_session_t *r);
static ngx_int_t ngx_stream_socks5_trojan_process_header(ngx_stream_session_t *r);

static ngx_conf_bitmask_t  ngx_stream_socks5_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};

#endif

static ngx_command_t ngx_stream_socks5_commands[] = {
    { ngx_string("socks5_pass"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_socks5_pass,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("socks5_client_header_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, client_header_timeout),
      NULL},

    { ngx_string("socks5_socket_keepalive"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, socket_keepalive),
      NULL },

    { ngx_string("socks5_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, timeout),
      NULL },

    { ngx_string("socks5_auth_basic_user_file"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_socks5_auth_basic_user_file,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, user_file),
      NULL },


    { ngx_string("socks5_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("socks5_upload_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, upload_rate),
      NULL },

    { ngx_string("socks5_download_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, download_rate),
      NULL },

    { ngx_string("socks5_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("socks5_upstream_username"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, upstream_username),
      NULL },


    { ngx_string("socks5_upstream_password"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, upstream_password),
      NULL },


    { ngx_string("socks5_next_upstream"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, next_upstream),
      NULL },

    { ngx_string("socks5_next_upstream_tries"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, next_upstream_tries),
      NULL },

    { ngx_string("socks5_next_upstream_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, next_upstream_timeout),
      NULL },

#if (NGX_STREAM_SSL)

    { ngx_string("socks5_ssl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_enable),
      NULL },

    { ngx_string("socks5_ssl_session_reuse"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_session_reuse),
      NULL },

    { ngx_string("socks5_ssl_protocols"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_protocols),
      &ngx_stream_socks5_ssl_protocols },

    { ngx_string("socks5_ssl_ciphers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("socks5_ssl_name"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_name),
      NULL },

    { ngx_string("socks5_ssl_server_name"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_server_name),
      NULL },

    { ngx_string("socks5_ssl_verify"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_verify),
      NULL },

    { ngx_string("socks5_ssl_verify_depth"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("socks5_ssl_trusted_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("socks5_ssl_crl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_crl),
      NULL },

    { ngx_string("socks5_ssl_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_certificate),
      NULL },

    { ngx_string("socks5_ssl_certificate_key"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_socks5_srv_conf_t, ssl_certificate_key),
      NULL },

    { ngx_string("socks5_ssl_password_file"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_socks5_ssl_password_file,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

#endif

    ngx_null_command
};

static ngx_stream_module_t  ngx_stream_socks5_module_ctx = {
    ngx_stream_socks5_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_socks5_create_srv_conf,      /* create server configuration */
    ngx_stream_socks5_merge_srv_conf        /* merge server configuration */
};

ngx_module_t  ngx_stream_socks5_module = {
    NGX_MODULE_V1,
    &ngx_stream_socks5_module_ctx,          /* module context */
    ngx_stream_socks5_commands,             /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_stream_variable_t ngx_stream_socks5_vars[] = {

    { ngx_string("socks5_dst_addr"), NULL,
      ngx_stream_socks5_dst_addr_variable, 0,
      NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("socks5_dst_port"), NULL,
      ngx_stream_socks5_dst_port_variable, 0,
      NGX_STREAM_VAR_NOCACHEABLE, 0 },

      ngx_stream_null_variable
};

static void
ngx_stream_socks5_handler(ngx_stream_session_t *s)
{
    ngx_event_t                      *rev;
    ngx_connection_t                 *c;
    ngx_stream_socks5_ctx_t          *ctx;
    ngx_stream_socks5_srv_conf_t     *sscf;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
    if(ctx == NULL) {
        ctx = ngx_http_socks5_create_ctx(s);
        if(ctx == NULL) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
        ngx_stream_set_ctx(s, ctx, ngx_stream_socks5_module);
    }

    s->log_handler = ngx_stream_socks5_log_error;

    c = s->connection;

    c->read->handler = ngx_stream_socks5_process_reqeust;
    c->write->handler = ngx_stream_socks5_dummy_handler;

    rev = c->read;
    if (!rev->ready) {
        ngx_add_timer(rev, sscf->client_header_timeout);

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_stream_socks5_finalize(s,
                                        NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }
    rev->handler(rev);
}

static void ngx_stream_socks5_process_reqeust(ngx_event_t *ev)
{
    ssize_t                        n;
    ngx_int_t                      rc;
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_socks5_ctx_t       *ctx;
    ngx_stream_socks5_srv_conf_t  *sscf;

    c = ev->data;
    s = c->data;
    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_stream_socks5_finalize(s, NGX_STREAM_SOCKS5_REQUEST_TIME_OUT);
        return;
    }

    if(c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
    n = ngx_stream_socks5_read_request(s, ctx);

    if(n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "client close connection");
        ngx_stream_socks5_finalize(s, NGX_OK);
        return;
    }

    rc = NGX_OK;
    if(n > 0) {
        if(ctx->downstream_phase == 0) {
            rc = ngx_stream_socks5_process_reqeust_first(s, &ctx->downstream_buf);
        } else if(ctx->downstream_phase == 1) {
        } else if(ctx->downstream_phase == 2) {
            rc = ngx_stream_socks5_process_reqeust_details(s, &ctx->downstream_buf);            
        }
    }

    if(rc == NGX_AGAIN && ctx->downstream_buf.last == ctx->downstream_buf.end) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "client request is to big");
        ngx_stream_socks5_finalize(s, NGX_STREAM_OK);
        return;
    }

    if(rc == NGX_ERROR) {
        return;
    }

    if(c->read->eof) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "client close connection");
        ngx_stream_socks5_finalize(s, NGX_OK);
        return;
    }

    if (!c->read->ready) {
        ngx_add_timer(c->read, sscf->client_header_timeout);

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_stream_socks5_finalize(s,
                                        NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }
    c->read->handler(c->read);
}

static ngx_int_t 
ngx_stream_socks5_process_reqeust_first(ngx_stream_session_t *s, ngx_buf_t *b)
{
    u_char                        *p, *last, buf[2];
    ssize_t                        n;
    ngx_int_t                      nm, method, rc;
    ngx_connection_t              *c;
    ngx_stream_socks5_srv_conf_t  *sscf;
    ngx_stream_socks5_ctx_t       *ctx;

    c = s->connection;
    p = b->pos;
    n = b->last - b->pos;
    if(n < 3) {
        return NGX_AGAIN;
    }

    nm = p[1];
    if(p[0] != '\x05' || nm == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "socks version error");
        ngx_stream_socks5_finalize(s, NGX_OK);
        return NGX_ERROR;
    }

    if(n < 2 + nm) {
        return NGX_AGAIN;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    method = sscf->auth ? 2 : 0;

    rc = NGX_ERROR;
    for(p = b->pos + 2, last = p + nm; p < last; p++) {
        if(*p == method) {
            buf[0] = '\x5';
            buf[1] = *p;
            rc = s->connection->send(s->connection, buf, 2);
            break;
        }
    }

    if (rc == NGX_AGAIN) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        ngx_add_timer(c->write, sscf->client_header_timeout);

        c->write->handler = ngx_stream_socks5_process_reqeust;

        return NGX_AGAIN;
    }

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_OK);
        return NGX_ERROR;
    }

    if (rc != 2) {

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "could not send 'METHOD selection message' at once");

        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);

        return NGX_ERROR;
    }
    b->pos += (nm + 2);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
    ctx->downstream_phase = method == 2 ? 1 : 2;
    return NGX_OK;
}

static ngx_int_t
ngx_stream_socks5_process_reqeust_details(ngx_stream_session_t *s,
    ngx_buf_t *b)
{
    u_char                       *p, buf[22];
    ssize_t                       n;
    ngx_int_t                     port;
    ngx_uint_t                    cmd, atyp;
    ngx_addr_t                    addr;
    ngx_sockaddr_t                sockaddr;
    ngx_connection_t              *c;
    ngx_stream_socks5_ctx_t       *ctx;

    c = s->connection;
    p = b->pos;
    n = b->last - b->pos;
    if(n < 10) {
        return NGX_AGAIN;
    }

    if(p[0] != 0x05 || p[2] != 0x00) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "socks request detail data error");
        ngx_stream_socks5_finalize(s, NGX_OK);
        return NGX_ERROR;
    }
    cmd = p[1];
    atyp = p[3];
    ngx_memzero(&addr, sizeof(addr));
    ngx_memzero(&sockaddr, sizeof(sockaddr));
    switch(atyp) {
        case 0x01: /* ipv4 */
            addr.sockaddr = (struct sockaddr*)&sockaddr.sockaddr_in;
            addr.socklen  = sizeof(sockaddr.sockaddr_in);
            sockaddr.sockaddr_in.sin_family = AF_INET;
            sockaddr.sockaddr_in.sin_port = *(in_port_t*)(p + 8);
            port = ntohs(sockaddr.sockaddr_in.sin_port);
            ngx_memcpy(&sockaddr.sockaddr_in.sin_addr.s_addr, p + 4, 4);
            p += 10;
        break;
        case 0x03: /* domain */
            if(n < 7 + p[4]) {
                return NGX_AGAIN;
            }

            addr.name.len = p[4];
            addr.name.data = p + 5;
            port = ntohs(*(in_port_t*)(p + 5 + p[4]));
            p += 4 + 1 + p[4] + 2;
        break;
#if (NGX_HAVE_INET6)
        case 0x04: /* ipv6 */
            if(n < 6 + 16) {
                return NGX_AGAIN;
            }

            addr.sockaddr = (struct sockaddr*)&sockaddr.sockaddr_in6;
            addr.socklen = sizeof(sockaddr.sockaddr_in6);
            sockaddr.sockaddr_in6.sin6_family = AF_INET6;
            sockaddr.sockaddr_in6.sin6_port = *(in_port_t*)(p + 4 + 16);
            port = ntohs(sockaddr.sockaddr_in6.sin6_port);
            ngx_memcpy(&sockaddr.sockaddr_in6.sin6_addr, p + 4, 16);
            p += 4 + 16 + 2;
        break;
#endif
        default:
            ngx_memset(buf, 0, sizeof(buf));
            buf[0] = '\x05'; buf[1] = '\x08';
            s->connection->send(s->connection, buf, 10);
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "(%ui) address type not supported", atyp);
            ngx_stream_socks5_finalize(s, NGX_OK);
            return NGX_ERROR;
        break;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
    ctx->cmd = cmd;
    if(addr.name.len) {
        ctx->dst_addr.name.data = ngx_pstrdup(c->pool, &addr.name);
        ctx->dst_addr.name.len = addr.name.len;
    }
    if(addr.socklen) {
        ctx->dst_addr.sockaddr = ngx_palloc(c->pool, addr.socklen);
        ngx_memcpy(ctx->dst_addr.sockaddr, addr.sockaddr, addr.socklen);
        ctx->dst_addr.socklen = addr.socklen;
    }
    
    ctx->dst_port = port;
    b->pos = p;
    switch(cmd) {
        case 0x01: /* CONNECT */
            ngx_stream_socks5_process_connect(s);
        break;
        case 0x02: /* BIND */
            ngx_memset(buf, 0, sizeof(buf));
            buf[0] = '\x05'; buf[1] = '\x07';
            s->connection->send(s->connection, buf, 10);
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ERROR, "(%ui) command not supported", cmd);
            ngx_stream_socks5_finalize(s, NGX_OK);
        break;
        case 0x03: /* UDP ASSOCIATE */
        break;
    }
    return NGX_OK;
}

static void
ngx_stream_socks5_process_connect(ngx_stream_session_t *s)
{
    ngx_str_t                        *host;
    ngx_uint_t                        i;
    ngx_connection_t                 *c;
    ngx_resolver_ctx_t               *rctx, temp;
    ngx_stream_upstream_t            *u;
    ngx_stream_socks5_ctx_t          *ctx;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_socks5_srv_conf_t     *sscf;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    c = s->connection;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    /* s->log_handler = ngx_stream_proxy_log_error; */

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR_ERR;

/*
    if (ngx_stream_proxy_set_local(s, u, sscf->local) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
*/

    if (sscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = ngx_time();

/*
    c->write->handler = ngx_stream_proxy_downstream_handler;
    c->read->handler = ngx_stream_proxy_downstream_handler;
*/

    s->upstream_states = ngx_array_create(c->pool, 1,
                                          sizeof(ngx_stream_upstream_state_t));

    if (s->upstream_states == NULL) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf = ctx->downstream_buf;

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    if (sscf->upstream_value) {
        if (ngx_stream_socks5_eval(s, ctx, sscf) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if(u->resolved == NULL) {
        uscf = sscf->upstream;
    } else {

#if (NGX_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = ngx_stream_get_module_main_conf(s, ngx_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_stream_upstream_create_round_robin_peer(s, u->resolved)
                != NGX_OK)
            {
                ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_stream_socks5_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

        rctx = ngx_resolve_start(cscf->resolver, &temp);
        if (rctx == NULL) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        rctx->name = *host;
        rctx->handler = ngx_stream_socks5_resolve_handler;
        rctx->data = s;
        rctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = rctx;

        if (ngx_resolve_name(rctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }
    
found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "no upstream configuration");
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NGX_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif


    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (sscf->next_upstream_tries
        && u->peer.tries > sscf->next_upstream_tries)
    {
        u->peer.tries = sscf->next_upstream_tries;
    }
    ngx_stream_socks5_connect(s);
}

static void
ngx_stream_socks5_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_stream_socks5_srv_conf_t    *sscf;
    ngx_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;


    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

    if (ngx_stream_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if (sscf->next_upstream_tries
        && u->peer.tries > sscf->next_upstream_tries)
    {
        u->peer.tries = sscf->next_upstream_tries;
    }

    ngx_stream_socks5_connect(s);
}

static void
ngx_stream_socks5_connect(ngx_stream_session_t *s)
{
    ngx_int_t                      rc;
    ngx_connection_t              *c, *pc;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = 0;

    if (u->state) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;
    u->state->response_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_stream_socks5_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_stream_socks5_next_upstream(s);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        ngx_stream_socks5_init_upstream(s);
        return;
    }

    pc->read->handler = ngx_stream_socks5_connect_handler;
    pc->write->handler = ngx_stream_socks5_connect_handler;

    ngx_add_timer(pc->write, sscf->connect_timeout);
}

static void
ngx_stream_socks5_init_upstream(ngx_stream_session_t *s)
{
    u_char                        *p;
    ngx_connection_t              *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t         *u;
    ngx_stream_core_srv_conf_t    *cscf;
    ngx_stream_socks5_srv_conf_t  *sscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != NGX_OK)
    {
        ngx_stream_socks5_next_upstream(s);
        return;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

#if (NGX_STREAM_SSL)

    if (pc->type == SOCK_STREAM && sscf->ssl_enable) {

        if (pc->ssl == NULL) {
            ngx_stream_socks5_ssl_init_connection(s);
            return;
        }
    }

#endif

    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = ngx_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = ngx_pnalloc(c->pool, sscf->buffer_size);
        if (p == NULL) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + sscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
        u->upstream_buf.temporary = 1;
    }

    u->upload_rate = ngx_stream_complex_value_size(s, sscf->upload_rate, 0);
    u->download_rate = ngx_stream_complex_value_size(s, sscf->download_rate, 0);

    ngx_stream_socks5_upstream_send_request(s, 1);
}

static void
ngx_stream_socks5_upstream_send_request(ngx_stream_session_t *s, ngx_uint_t do_write)
{
    ngx_int_t                         rc;
    ngx_connection_t                 *pc;
    ngx_stream_upstream_t            *u;
    ngx_stream_socks5_ctx_t          *ctx;
    ngx_stream_socks5_srv_conf_t     *sscf;

    u = s->upstream;
    pc = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "stream socks5 send request");

    if (u->state->connect_time == (ngx_msec_t) -1) {
        u->state->connect_time = ngx_current_msec - u->start_time;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    pc->log->action = "sending request to upstream";
    if(ctx->send_request) {
        rc = ctx->send_request(s);
    } else {
        rc = NGX_OK;
    }

    if (rc == NGX_ERROR || rc == NGX_AGAIN) {
        ngx_stream_socks5_next_upstream(s);
        return;
    }

   /*  or  */
   /*
    * rc == NGX_OK 发送成功，不需要处理upstream response head
    * NGX_DONE     发送成功，需要处理upstream response head
    */

    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if(rc == NGX_DONE) {
        pc->read->handler = ngx_stream_socks5_process_header_handler;
        ngx_add_timer(pc->read, sscf->timeout);
        if (pc->read->ready) {
            ngx_stream_socks5_process_header(s);
            return;
        }
    }
    ngx_stream_socks5_send_response(s);
}

static void
ngx_stream_socks5_process_header_handler(ngx_event_t *ev)
{
    ngx_connection_t              *c, *pc;
    ngx_stream_session_t          *s;

    c = ev->data;
    s = c->data;
    pc = s->upstream->peer.connection;

    if(ev->timedout) {
        ngx_log_debug0(NGX_LOG_ERR, pc->log, 0,
            "stream socks5 receive header timeout");
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_stream_socks5_process_header(s);
}

static void
ngx_stream_socks5_process_header(ngx_stream_session_t *s)
{
    ssize_t                          n;
    ngx_int_t                        rc;
    ngx_connection_t                *pc;
    ngx_stream_upstream_t           *u;
    ngx_stream_socks5_ctx_t         *ctx;
    ngx_stream_socks5_srv_conf_t    *sscf;

    u = s->upstream;
    pc = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "stream socks5 process header");

    pc->log->action = "reading response header from upstream";

    if (pc->read->timedout) {
        ngx_stream_socks5_next_upstream(s);
        return;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
/*
    if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }
*/

    if (u->upstream_buf.start == NULL) {
        u->upstream_buf.start = ngx_pnalloc(pc->pool, sscf->buffer_size);
        if (u->upstream_buf.start == NULL) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.end = u->upstream_buf.start + sscf->buffer_size;
        u->upstream_buf.pos = u->upstream_buf.start;
        u->upstream_buf.last = u->upstream_buf.start;
        u->upstream_buf.temporary = 1;
    }

    for ( ;; ) {

        n = pc->recv(pc, u->upstream_buf.last, u->upstream_buf.end - u->upstream_buf.last);

        if (n == NGX_AGAIN) {

            if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
                ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            return;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                          "upstream prematurely closed connection");
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_stream_socks5_next_upstream(s);
            return;
        }

        u->state->bytes_received += n;
        u->upstream_buf.last += n;

        rc = ctx->process_header(s);

       if (rc == NGX_AGAIN) {

            if (u->upstream_buf.last == u->upstream_buf.end) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream sent too big header");

                ngx_stream_socks5_next_upstream(s);
                return;
            }

            continue;
        }

        break;
    }

/*
    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }
*/

    if (rc == NGX_ERROR) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == NGX_OK */

    /* u->state->header_time = ngx_current_msec - u->start_time; */

    ngx_stream_socks5_send_response(s);
}

static void
ngx_stream_socks5_send_response(ngx_stream_session_t *s)
{
    u_char                           buf[256], *p;
    ssize_t                          n, size;
    ngx_connection_t                *c, *pc;
    ngx_stream_upstream_t           *u;
    ngx_stream_socks5_ctx_t         *ctx;
    ngx_stream_socks5_srv_conf_t    *sscf;

    c = s->connection;
    u = s->upstream;
    pc = u->peer.connection;
    sscf =ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (ngx_connection_local_sockaddr(pc, NULL, 0) != NGX_OK) {

        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = buf;
    p[0] = '\x05'; p[1] = '\x00'; p[2] = '\x00';
    if(pc->local_sockaddr->sa_family == AF_INET6) {
#if (NGX_HAVE_INET6)
        p[3] = '\x01';
        ngx_memcpy(p + 4, &((struct sockaddr_in6*)pc->local_sockaddr)->sin6_addr, sizeof(in6_addr_t));
        p += (4 + sizeof(in6_addr_t));
        *(in_port_t*)p = ((struct sockaddr_in6*)pc->local_sockaddr)->sin6_port;
        p += 2;
#endif
    } else {
        p[3] = '\x01';
        *(in_addr_t*)(p + 4) = ((struct sockaddr_in*)pc->local_sockaddr)->sin_addr.s_addr;
        p += 8;
        *(in_port_t*)p = ((struct sockaddr_in*)pc->local_sockaddr)->sin_port;
        p += 2;
    } 

    size = p - buf;
    n = c->send(c, buf, size);
    if(n != size) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->connected = 1;

    c->read->handler = ngx_stream_socks5_downstream_handler;
    c->write->handler = ngx_stream_socks5_downstream_handler;

    pc->read->handler = ngx_stream_socks5_upstream_handler;
    pc->write->handler = ngx_stream_socks5_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }
    ngx_add_timer(c->read, sscf->timeout);
    ngx_add_timer(pc->read, sscf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }
    ngx_stream_socks5_process(s, 0, 1);
    return;
}

static char *
ngx_stream_socks5_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_socks5_srv_conf_t *sscf = conf;

    ngx_str_t  *value;

    if (sscf->ssl_passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (sscf->ssl_passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void
ngx_stream_socks5_ssl_init_connection(ngx_stream_session_t *s)
{
    ngx_int_t                      rc;
    ngx_connection_t              *pc;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    u = s->upstream;

    pc = u->peer.connection;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if (ngx_ssl_create_connection(sscf->ssl, pc, NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (sscf->ssl_server_name || sscf->ssl_verify) {
        if (ngx_stream_socks5_ssl_name(s) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (sscf->ssl_session_reuse) {
        pc->ssl->save_session = ngx_stream_socks5_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(pc);

    if (rc == NGX_AGAIN) {

        if (!pc->write->timer_set) {
            ngx_add_timer(pc->write, sscf->connect_timeout);
        }

        pc->ssl->handler = ngx_stream_socks5_ssl_handshake;
        return;
    }

    ngx_stream_socks5_ssl_handshake(pc);
}

static void
ngx_stream_socks5_ssl_handshake(ngx_connection_t *pc)
{
    long                           rc;
    ngx_stream_session_t          *s;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    s = pc->data;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if (pc->ssl->handshaked) {

        if (sscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (ngx_ssl_check_host(pc, &u->ssl_name) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        ngx_stream_socks5_init_upstream(s);

        return;
    }

failed:

    ngx_stream_socks5_next_upstream(s);
}

static void
ngx_stream_socks5_ssl_save_session(ngx_connection_t *c)
{
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}

static ngx_int_t
ngx_stream_socks5_ssl_name(ngx_stream_session_t *s)
{
    u_char                        *p, *last;
    ngx_str_t                      name;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    u = s->upstream;

    if (sscf->ssl_name) {
        if (ngx_stream_complex_value(s, sscf->ssl_name, &name) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = ngx_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = ngx_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!sscf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = ngx_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NGX_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_socks5_eval(ngx_stream_session_t *s, ngx_stream_socks5_ctx_t *ctx,
    ngx_stream_socks5_srv_conf_t *sscf)
{
    size_t                  add;
    u_short                 port;
    ngx_str_t               host;
    ngx_url_t               url;
    ngx_stream_upstream_t  *u;

    if (ngx_stream_complex_value(s, sscf->upstream_value, &host) != NGX_OK) {
        return NGX_ERROR;
    }

    if(host.len == 4 && ngx_strncasecmp(host.data, (u_char *) "none", 4) == 0) {

        add = 4;
        port = 0;
        ctx->upstream_protocol = 0;
#if (NGX_STREAM_SSL)
    } else if(host.len > 9
      && ngx_strncasecmp(host.data, (u_char *) "trojan://", 9) == 0)
    {
        ctx->ssl_enable = 1;

        add = 9;
        port = 443;
        ctx->upstream_protocol = 3;
    } else if (host.len > 8
      && ngx_strncasecmp(host.data, (u_char *) "https://", 8) == 0)
    {
        ctx->ssl_enable = 1;

        add = 8;
        port = 443;
        ctx->upstream_protocol = 2;
#endif /* (NGX_HTTP_SSL) */
    } else if(host.len > 7
      && ngx_strncasecmp(host.data, (u_char *) "http://", 7) == 0)
    {
        add = 7;
        port = 80;
        ctx->upstream_protocol = 2;
    } else {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "invalid URL prefix in \"%V\"", &host);
        return NGX_ERROR;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = host.len - add;
    url.url.data = host.data + add;
    url.default_port = port;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u = s->upstream;

    u->resolved = ngx_pcalloc(s->connection->pool,
                              sizeof(ngx_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}

static ssize_t
ngx_stream_socks5_read_request(ngx_stream_session_t *s,
    ngx_stream_socks5_ctx_t *ctx)
{
    ssize_t                    n, size;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;

    c = s->connection;
    b = &ctx->downstream_buf;

    if(b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
    }

    if(c->read->eof || c->read->error) {
        return b->last - b->pos;
    }

    size = b->end - b->last;
    if (size && c->read->ready) {
        n = c->recv(c, b->last, size);

        if (n == NGX_AGAIN) {
            if(b->last - b->pos) {
                return b->last - b->pos;
            }
            
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            c->read->eof = 1;
            n = 0;
        }

        if(n > 0) {
            b->last = b->last + n;
            s->received += n;
        }
        return b->last - b->pos;
    }

    return (b->last - b->pos) ? (b->last - b->pos) : NGX_AGAIN;
}

static void
ngx_stream_socks5_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_socks5_process_connection(ev, ev->write);
}

static void
ngx_stream_socks5_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_socks5_process_connection(ev, !ev->write);
}

static void
ngx_stream_socks5_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t              *c, *pc;
    ngx_stream_session_t          *s;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
        ngx_stream_socks5_finalize(s, NGX_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u ? u->peer.connection : NULL;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    if (ev->timedout) {
        ev->timedout = 0;

        /* stream proxy 模块使用 delayed 标记来处理限速 */
        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    ngx_stream_socks5_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }


                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, sscf->timeout);
                }

                return;
            }
        } else {

            if(pc && pc->type == SOCK_DGRAM) {
                /* 处理 UDP 正常关闭 */
            }

            ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");

            ngx_stream_socks5_finalize(s, NGX_STREAM_OK);

            return;

        }
    } else if(ev->delayed) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && (u == NULL || !u->connected)) {
        return;
    }

    ngx_stream_socks5_process(s, from_upstream, ev->write);
}

static void
ngx_stream_socks5_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
        ngx_stream_socks5_next_upstream(s);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (ngx_stream_socks5_test_connect(c) != NGX_OK) {
        ngx_stream_socks5_next_upstream(s);
        return;
    }

    ngx_stream_socks5_init_upstream(s);
}

static ngx_int_t
ngx_stream_socks5_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_stream_socks5_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    flags, *packets;
    ngx_msec_t                    delay;
    ngx_chain_t                  *cl, **ll, **out, **busy;
    ngx_connection_t              *c, *pc, *src, *dst;
    ngx_stream_filter_pt           write_filter;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_ctx_t       *ctx;
    ngx_stream_socks5_srv_conf_t  *sscf;

    u_char                         hex[4096];
    u = s->upstream;

    c = s->connection;
    pc = u && u->connected ? u->peer.connection : NULL;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        write_filter = ctx->dwonstream_writer;
        b = &u->upstream_buf;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;
        write_filter = ctx->upstream_writer;
        b = &u->downstream_buf;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    for ( ;; ) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                rc = write_filter(s, *out, from_upstream);

                if (rc == NGX_ERROR) {
                    ngx_stream_socks5_finalize(s, NGX_STREAM_OK);
                    return;
                }

                ngx_chain_update_chains(c->pool, &u->free, busy, out,
                                      (ngx_buf_tag_t) &ngx_stream_socks5_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed
            && !src->read->error)
        {
            if (limit_rate) {
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);
            if(n > 0) {
                ngx_hex_dump(hex, b->last, ngx_min(n, 2047));
                hex[ngx_min(n, 2047)*2] = '\x00';
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                        "receive data(%d): %s",from_upstream, hex);
            }

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec
                                                    - u->start_time;
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = ngx_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    ngx_stream_socks5_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_socks5_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                (*packets)++;
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    if (ngx_stream_socks5_test_finalize(s, from_upstream) == NGX_OK) {
        return;
    }

    if(src) {
        flags = src->read->eof ? NGX_CLOSE_EVENT : 0;

        if (ngx_handle_read_event(src->read, flags) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (dst) {
        if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, sscf->timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}

static ngx_int_t
ngx_stream_socks5_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream)
{
    ngx_connection_t              *c, *pc;
    ngx_log_handler_pt             handler;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    c = s->connection;
    u = s->upstream;
    pc = u && u->connected ? u->peer.connection : NULL;

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NGX_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_stream_socks5_finalize(s, NGX_STREAM_OK);

    return NGX_OK;}

static void
ngx_stream_socks5_next_upstream(ngx_stream_session_t *s)
{
    ngx_msec_t                     timeout;
    ngx_connection_t              *pc;
    ngx_stream_upstream_t         *u;
    ngx_stream_socks5_srv_conf_t  *sscf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream socks5 next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

/*
    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }
*/


    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    timeout = sscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !sscf->next_upstream
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_stream_socks5_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close socks5 upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    ngx_stream_socks5_connect(s);
}

static void
ngx_stream_socks5_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

   if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}

static void
ngx_stream_socks5_dummy_handler(ngx_event_t *ev)
{
    ngx_connection_t   *c;
    c = ev->data;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "socks5 dummy handler");
}

static u_char *
ngx_stream_socks5_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}

static void *
ngx_stream_socks5_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_socks5_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_socks5_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->client_header_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->socket_keepalive = NGX_CONF_UNSET;

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->next_upstream = NGX_CONF_UNSET;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;

#if (NGX_STREAM_SSL)
    conf->ssl_enable = NGX_CONF_UNSET;
    conf->ssl_session_reuse = NGX_CONF_UNSET;
    conf->ssl_server_name = NGX_CONF_UNSET;
    conf->ssl_verify = NGX_CONF_UNSET;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->ssl_passwords = NGX_CONF_UNSET_PTR;
#endif

    return conf;
}

static char *
ngx_stream_socks5_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_socks5_srv_conf_t *prev = parent;
    ngx_stream_socks5_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->client_header_timeout,
                              prev->client_header_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    ngx_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

#if (NGX_STREAM_SSL)

    ngx_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    ngx_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                               |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    if (conf->ssl_name == NULL) {
        conf->ssl_name = prev->ssl_name;
    }

    ngx_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    ngx_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");

    ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl_enable && ngx_stream_socks5_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    return NGX_CONF_OK;
}

#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_socks5_set_ssl(ngx_conf_t *cf, ngx_stream_socks5_srv_conf_t *sscf)
{
    ngx_pool_cleanup_t  *cln;

    sscf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (sscf->ssl == NULL) {
        return NGX_ERROR;
    }

    sscf->ssl->log = cf->log;

    if (ngx_ssl_create(sscf->ssl, sscf->ssl_protocols, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(sscf->ssl);
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = sscf->ssl;

    if (sscf->ssl_certificate.len) {

        if (sscf->ssl_certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &sscf->ssl_certificate);
            return NGX_ERROR;
        }

        if (ngx_ssl_certificate(cf, sscf->ssl, &sscf->ssl_certificate,
                                &sscf->ssl_certificate_key, sscf->ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_ciphers(cf, sscf->ssl, &sscf->ssl_ciphers, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (sscf->ssl_verify) {
        if (sscf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, sscf->ssl,
                                        &sscf->ssl_trusted_certificate,
                                        sscf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, sscf->ssl, &sscf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_client_session_cache(cf, sscf->ssl, sscf->ssl_session_reuse)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif

ngx_stream_socks5_ctx_t *
ngx_http_socks5_create_ctx(ngx_stream_session_t *s)
{
    u_char                           *p;
    ngx_connection_t                 *c;
    ngx_stream_socks5_ctx_t          *ctx;
    ngx_stream_socks5_srv_conf_t     *sscf;

    c = s->connection;
    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_socks5_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);

    p = ngx_pnalloc(c->pool, sscf->buffer_size);
    if (p == NULL) {
        return NULL;
    }

    ctx->downstream_buf.start = p;
    ctx->downstream_buf.end = p + sscf->buffer_size;
    ctx->downstream_buf.pos = p;
    ctx->downstream_buf.last = p;

    ctx->dwonstream_writer = ngx_stream_top_filter;
    ctx->upstream_writer = ngx_stream_top_filter;
    if(sscf->upstream_protocol == 3) {
        /* trojan */
        ctx->send_request = ngx_stream_socks5_trojan_send_request;
        ctx->resend_request = ngx_stream_socks5_trojan_resend_request;
        ctx->process_header = ngx_stream_socks5_trojan_process_header;
    }
    
    return ctx;
}

static char *
ngx_stream_socks5_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_socks5_srv_conf_t *sscf = conf;

    size_t                               add;
    u_short                              port;
    ngx_url_t                            u;
    ngx_str_t                           *value, *url;
    ngx_stream_complex_value_t           cv;
    ngx_stream_core_srv_conf_t          *cscf;
    ngx_stream_compile_complex_value_t   ccv;

    if (sscf->upstream || sscf->upstream_value || sscf->upstream_protocol != 0) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_socks5_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths) {
        sscf->upstream_value = ngx_palloc(cf->pool,
                                          sizeof(ngx_stream_complex_value_t));
        if (sscf->upstream_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *sscf->upstream_value = cv;

        return NGX_CONF_OK;
    }

    if (url->len == 4 && ngx_strncasecmp(url->data, (u_char *) "none", 4) == 0) {
        sscf->upstream_protocol = 0;

        return NGX_CONF_OK;
    } else if(ngx_strncasecmp(url->data, (u_char *) "trojan://", 9) == 0) {

#if (NGX_STREAM_SSL)
        sscf->ssl_enable = 1;

        add = 9;
        port = 443;
        sscf->upstream_protocol = 3;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;
        sscf->upstream_protocol = 2;
    } else if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

#if (NGX_STREAM_SSL)
        sscf->ssl_enable = 1;

        add = 8;
        port = 443;
        sscf->upstream_protocol = 2;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    sscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
    if (sscf->upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    sscf->vars.schema.len = add;
    sscf->vars.schema.data = url->data;
    sscf->vars.key_start = sscf->vars.schema;

    ngx_stream_socks5_set_vars(&u, &sscf->vars);
    return NGX_CONF_OK;
}

static char *
ngx_stream_socks5_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_socks5_srv_conf_t *sscf = conf;

    ngx_str_t                         *value;
    ngx_stream_compile_complex_value_t   ccv;

    if (sscf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &sscf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    sscf->auth = 1;
    return NGX_CONF_OK;
}

static void
ngx_stream_socks5_set_vars(ngx_url_t *u, ngx_stream_socks5_vars_t *v)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {

            v->host_header = u->host;

            if (u->default_port == 80) {
                ngx_str_set(&v->port, "80");

            } else {
                ngx_str_set(&v->port, "443");
            }

        } else {
            v->host_header.len = u->host.len + 1 + u->port_text.len;
            v->host_header.data = u->host.data;
            v->port = u->port_text;
        }

        v->key_start.len += v->host_header.len;

    } else {
        ngx_str_set(&v->host_header, "localhost");
        ngx_str_null(&v->port);
        v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
    }

    v->uri = u->uri;
}

#if (NGX_STREAM_SSL)

#include <openssl/sha.h>

/*
 * trojan 
 */
static ngx_int_t
ngx_stream_socks5_trojan_send_request(ngx_stream_session_t *s)
{
    ssize_t                          n, size;
    ngx_connection_t                *pc;
    ngx_stream_socks5_srv_conf_t    *sscf;
    ngx_stream_socks5_ctx_t         *ctx;
    u_char                          *p, buf[512];

    pc = s->upstream->peer.connection;
    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_socks5_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);

    SHA224(sscf->upstream_password.data, sscf->upstream_password.len, buf + 56);
    ngx_hex_dump(buf, buf + 56, 28);
    buf[56] = '\x0d'; buf[57] = '\x0a';
    p = buf + 58;
    p[0] = ctx->cmd;
    if(ctx->dst_addr.sockaddr == NULL) {
        p[1] = '\x03';
        p[2] = ctx->dst_addr.name.len;
        ngx_memcpy(p + 3, ctx->dst_addr.name.data, p[2]);
        p += (3 + p[2]);
    } else if(ctx->dst_addr.sockaddr->sa_family == AF_INET) {
        p[1] = '\x01';
        *(in_addr_t*)(p + 2) = ((struct sockaddr_in*)ctx->dst_addr.sockaddr)->sin_addr.s_addr;
        p += (2 + 4);
    } else if(ctx->dst_addr.sockaddr->sa_family == AF_INET6) {
        p[1] = '\x04';
        ngx_memcpy(p + 2, &((struct sockaddr_in6*)ctx->dst_addr.sockaddr)->sin6_addr, sizeof(in6_addr_t));
        p += (2 + sizeof(in6_addr_t));
    }

    *(in_port_t *)p =  htons(ctx->dst_port);
    p += 2;
    p[0] = '\x0d'; p[1] = '\x0a';
    p += 2;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (n != size) {
        ngx_stream_socks5_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_stream_socks5_trojan_resend_request(ngx_stream_session_t *s)
{
    return ngx_stream_socks5_trojan_send_request(s);
}

static ngx_int_t
ngx_stream_socks5_trojan_process_header(ngx_stream_session_t *s)
{
    return NGX_OK;
}

#endif

static ngx_int_t
ngx_stream_socks5_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_socks5_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_socks5_dst_addr_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_socks5_ctx_t       *ctx;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
    if(!ctx || ctx->dst_addr.name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->dst_addr.name.len;
    v->data = ctx->dst_addr.name.data;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_socks5_dst_port_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_socks5_ctx_t       *ctx;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_socks5_module);
    if(!ctx || ctx->dst_addr.name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(s->connection->pool, sizeof(65535) - 1);
    if(v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%ui", ctx->dst_port) - v->data;

    return NGX_OK;
}
