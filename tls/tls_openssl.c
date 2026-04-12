/*
* tls_openssl.c - TLS 模块，基于 OpenSSL 实现（非 Windows 平台）
* 提供与 tls_windows.c 完全一致的 Lua 接口
*/

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "lua.h"
#include "lauxlib.h"

/* ========== BIO 读取临时缓冲区大小 ========== */
#define TLS_BIO_BUFSIZE 4096

/* ========== 结构体定义 ========== */

/* TLS 上下文（封装 SSL_CTX） */
struct ssl_ctx {
    SSL_CTX* ctx;
};

/* TLS 连接对象（封装 SSL 和 BIO 对） */
struct tls_context {
    SSL*  ssl;
    BIO*  in_bio;       /* 用于向 SSL 输入数据（网络侧 -> SSL） */
    BIO*  out_bio;      /* 用于从 SSL 读取输出数据（SSL -> 网络侧） */
    bool  is_server;
    bool  is_close;
    bool  handshake_done;
};

/* ========== 错误处理辅助函数 ========== */

static const char*
_ssl_error_string(void) {
    unsigned long err = ERR_get_error();
    if (err == 0)
        return "unknown error";
    return ERR_reason_error_string(err);
}

/* ========== ssl_ctx 辅助函数 ========== */

static struct ssl_ctx*
_check_sslctx(lua_State* L, int idx) {
    struct ssl_ctx* ctx_p = (struct ssl_ctx*)lua_touserdata(L, idx);
    if (!ctx_p) {
        luaL_error(L, "need sslctx");
    }
    return ctx_p;
}

/* ========== tls_context 辅助函数 ========== */

static struct tls_context*
_check_context(lua_State* L, int idx) {
    struct tls_context* tls_p = (struct tls_context*)lua_touserdata(L, idx);
    if (!tls_p) {
        luaL_error(L, "need tls context");
    }
    if (tls_p->is_close) {
        luaL_error(L, "context is closed");
    }
    return tls_p;
}

/* ========== 从 out_bio 读取数据并压入 Lua 栈 ========== */

static int
_bio_read_output(lua_State* L, BIO* out_bio) {
    int pending = BIO_ctrl_pending(out_bio);
    if (pending <= 0)
        return 0;
    char* buf = (char*)malloc(pending);
    if (!buf)
        return luaL_error(L, "out of memory");
    int n = BIO_read(out_bio, buf, pending);
    if (n <= 0) {
        free(buf);
        return 0;
    }
    lua_pushlstring(L, buf, n);
    free(buf);
    return 1;
}

/* ========== ctx:set_cert 实现 ========== */

static int
_lctx_cert(lua_State* L) {
    struct ssl_ctx* ctx_p = _check_sslctx(L, 1);
    const char* certfile = lua_tostring(L, 2);
    const char* keyfile = lua_tostring(L, 3);
    if (!certfile) luaL_error(L, "need certfile");
    if (!keyfile) luaL_error(L, "need private key file");

    /* 加载证书文件 */
    if (SSL_CTX_use_certificate_file(ctx_p->ctx, certfile, SSL_FILETYPE_PEM) != 1) {
        return luaL_error(L, "SSL_CTX_use_certificate_file failed: %s", _ssl_error_string());
    }

    /* 加载私钥文件 */
    if (SSL_CTX_use_PrivateKey_file(ctx_p->ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
        return luaL_error(L, "SSL_CTX_use_PrivateKey_file failed: %s", _ssl_error_string());
    }

    /* 验证证书与私钥匹配 */
    if (SSL_CTX_check_private_key(ctx_p->ctx) != 1) {
        return luaL_error(L, "SSL_CTX_check_private_key failed: certificate and private key do not match");
    }

    return 0;
}

/* ========== ctx:__gc 实现 ========== */

static int
_lctx_gc(lua_State* L) {
    struct ssl_ctx* ctx_p = (struct ssl_ctx*)lua_touserdata(L, 1);
    if (!ctx_p) return 0;
    if (ctx_p->ctx) {
        SSL_CTX_free(ctx_p->ctx);
        ctx_p->ctx = NULL;
    }
    return 0;
}

/* ========== tls.newctx 实现 ========== */

static int
lnew_ctx(lua_State* L) {
    struct ssl_ctx* ctx_p = (struct ssl_ctx*)lua_newuserdatauv(L, sizeof(*ctx_p), 0);
    memset(ctx_p, 0, sizeof(*ctx_p));

    ctx_p->ctx = SSL_CTX_new(TLS_method());
    if (!ctx_p->ctx) {
        return luaL_error(L, "SSL_CTX_new failed: %s", _ssl_error_string());
    }

    /* 设置最低协议版本为 TLS 1.2 */
    SSL_CTX_set_min_proto_version(ctx_p->ctx, TLS1_2_VERSION);

    /* 加载系统默认 CA 证书 */
    SSL_CTX_set_default_verify_paths(ctx_p->ctx);

    /* 设置元表 */
    if (luaL_newmetatable(L, "_TLS_SSLCTX_METATABLE_")) {
        luaL_Reg l[] = {
            {"set_cert", _lctx_cert},
            {NULL, NULL},
        };
        luaL_newlib(L, l);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, _lctx_gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    return 1;
}

/* ========== tls_context:finished 实现 ========== */

static int
_ltls_context_finished(lua_State* L) {
    struct tls_context* tls_p = _check_context(L, 1);
    lua_pushboolean(L, tls_p->handshake_done);
    return 1;
}

/* ========== tls_context:close 实现 ========== */

static int
_ltls_context_close(lua_State* L) {
    struct tls_context* tls_p = (struct tls_context*)lua_touserdata(L, 1);
    if (!tls_p) return 0;
    if (!tls_p->is_close) {
        if (tls_p->ssl) {
            /* SSL_free 会自动释放关联的 BIO */
            SSL_free(tls_p->ssl);
            tls_p->ssl = NULL;
            tls_p->in_bio = NULL;
            tls_p->out_bio = NULL;
        }
        tls_p->is_close = true;
    }
    return 0;
}

/* ========== tls_context:handshake 实现 ========== */

static int
_ltls_context_handshake(lua_State* L) {
    struct tls_context* tls_p = _check_context(L, 1);
    size_t slen = 0;
    const char* exchange = lua_tolstring(L, 2, &slen);

    if (tls_p->handshake_done) {
        return luaL_error(L, "handshake is finished");
    }

    /* 将收到的数据写入 in_bio */
    if (slen > 0 && exchange != NULL) {
        BIO_write(tls_p->in_bio, exchange, (int)slen);
    }

    int ret = SSL_do_handshake(tls_p->ssl);
    if (ret == 1) {
        /* 握手完成 */
        tls_p->handshake_done = true;
        return _bio_read_output(L, tls_p->out_bio);
    }

    int err = SSL_get_error(tls_p->ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
        /* 需要更多数据，尝试返回已生成的输出 */
        return _bio_read_output(L, tls_p->out_bio);
    }

    /* 其他错误 */
    return luaL_error(L, "SSL_do_handshake failed: %s", _ssl_error_string());
}

/* ========== tls_context:read 实现 ========== */

static int
_ltls_context_read(lua_State* L) {
    struct tls_context* tls_p = _check_context(L, 1);
    size_t slen = 0;
    const char* encrypted_data = lua_tolstring(L, 2, &slen);

    /* 将加密数据写入 in_bio */
    if (slen > 0 && encrypted_data) {
        BIO_write(tls_p->in_bio, encrypted_data, (int)slen);
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    char buf[TLS_BIO_BUFSIZE];
    for (;;) {
        int n = SSL_read(tls_p->ssl, buf, sizeof(buf));
        if (n <= 0) {
            int err = SSL_get_error(tls_p->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_ZERO_RETURN) {
                break;
            }
            /* 忽略其他错误，返回已解密的数据 */
            break;
        }
        luaL_addlstring(&b, buf, n);
    }

    luaL_pushresult(&b);
    return 1;
}

/* ========== tls_context:write 实现 ========== */

static int
_ltls_context_write(lua_State* L) {
    struct tls_context* tls_p = _check_context(L, 1);
    size_t slen = 0;
    const char* plain_data = lua_tolstring(L, 2, &slen);

    if (!plain_data || slen == 0) {
        lua_pushstring(L, "");
        return 1;
    }

    int written = SSL_write(tls_p->ssl, plain_data, (int)slen);
    if (written <= 0) {
        return luaL_error(L, "SSL_write failed: %s", _ssl_error_string());
    }

    /* 从 out_bio 读取加密后的数据 */
    return _bio_read_output(L, tls_p->out_bio);
}

/* ========== tls.newtls 实现 ========== */

static int
lnew_tls(lua_State* L) {
    const char* method = luaL_checkstring(L, 1);
    struct ssl_ctx* ctx_p = _check_sslctx(L, 2);

    struct tls_context* tls_p = (struct tls_context*)lua_newuserdatauv(L, sizeof(*tls_p), 1);
    memset(tls_p, 0, sizeof(*tls_p));

    tls_p->ssl = SSL_new(ctx_p->ctx);
    if (!tls_p->ssl) {
        return luaL_error(L, "SSL_new failed: %s", _ssl_error_string());
    }

    tls_p->in_bio = BIO_new(BIO_s_mem());
    tls_p->out_bio = BIO_new(BIO_s_mem());
    if (!tls_p->in_bio || !tls_p->out_bio) {
        SSL_free(tls_p->ssl);
        tls_p->ssl = NULL;
        return luaL_error(L, "BIO_new failed");
    }

    /* 绑定 BIO 对到 SSL（SSL_set_bio 会接管 BIO 的所有权） */
    SSL_set_bio(tls_p->ssl, tls_p->in_bio, tls_p->out_bio);

    tls_p->is_close = false;
    tls_p->handshake_done = false;

    /* 保存 ctx 引用，防止 GC */
    lua_pushvalue(L, 2);
    lua_setiuservalue(L, -2, 1);

    if (strcmp(method, "client") == 0) {
        tls_p->is_server = false;
        SSL_set_connect_state(tls_p->ssl);
        /* 设置 SNI 主机名（bee.net 的设计：在 newtls 时设置，而非 handshake 时） */
        if (!lua_isnoneornil(L, 3)) {
            const char* hostname = luaL_checkstring(L, 3);
            SSL_set_tlsext_host_name(tls_p->ssl, hostname);
        }
    } else if (strcmp(method, "server") == 0) {
        tls_p->is_server = true;
        SSL_set_accept_state(tls_p->ssl);
    } else {
        return luaL_error(L, "invalid method:%s e.g[server, client]", method);
    }

    /* 设置元表 */
    if (luaL_newmetatable(L, "_TLS_CONTEXT_METATABLE_")) {
        luaL_Reg l[] = {
            {"close", _ltls_context_close},
            {"finished", _ltls_context_finished},
            {"handshake", _ltls_context_handshake},
            {"read", _ltls_context_read},
            {"write", _ltls_context_write},
            {NULL, NULL},
        };
        luaL_newlib(L, l);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, _ltls_context_close);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    return 1;
}

/* ========== 模块入口 ========== */

__attribute__((visibility("default")))
int luaopen_tls(lua_State* L) {
    luaL_Reg l[] = {
        {"newctx", lnew_ctx},
        {"newtls", lnew_tls},
        {NULL, NULL},
    };
    luaL_checkversion(L);
    luaL_newlib(L, l);
    return 1;
}
