/*
 * tls_macos.c - TLS 模块，基于 macOS SecureTransport 实现
 * 提供与 tls_windows.c / tls_openssl.c 完全一致的 Lua 接口
 *
 * 注意：SecureTransport API 在 macOS 10.15 中被标记为弃用，
 * 但在所有 macOS 版本上仍可正常使用。
 * 未来可迁移至 Network.framework。
 */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

#include "lua.h"
#include "lauxlib.h"

/* ========== 动态缓冲区 ========== */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    size_t   rpos;
} tls_buf_t;

#define TLS_BUF_INIT_SIZE 16384

static bool
buf_init(tls_buf_t *b) {
    b->data = (uint8_t *)malloc(TLS_BUF_INIT_SIZE);
    if (!b->data) return false;
    b->len = b->rpos = 0;
    b->cap = TLS_BUF_INIT_SIZE;
    return true;
}

static void
buf_free(tls_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = b->rpos = 0;
}

static bool
buf_write(tls_buf_t *b, const void *data, size_t len) {
    if (b->rpos > 0) {
        size_t unread = b->len - b->rpos;
        if (unread > 0) memmove(b->data, b->data + b->rpos, unread);
        b->len = unread;
        b->rpos = 0;
    }
    if (b->len + len > b->cap) {
        size_t ncap = b->cap * 2;
        if (ncap < b->len + len) ncap = b->len + len;
        uint8_t *nd = (uint8_t *)realloc(b->data, ncap);
        if (!nd) return false;
        b->data = nd;
        b->cap  = ncap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return true;
}

static size_t
buf_readable(const tls_buf_t *b) {
    return b->len - b->rpos;
}

static size_t
buf_read(tls_buf_t *b, void *dst, size_t want) {
    size_t avail = buf_readable(b);
    size_t n = avail < want ? avail : want;
    memcpy(dst, b->data + b->rpos, n);
    b->rpos += n;
    return n;
}

/* ========== 结构体定义 ========== */

struct ssl_ctx {
    SecIdentityRef identity;  /* 服务端证书+私钥；客户端模式为 NULL */
};

struct tls_context {
    SSLContextRef ssl;
    tls_buf_t     in_buf;    /* 外部 → SSL（接收网络数据） */
    tls_buf_t     out_buf;   /* SSL → 外部（待发送数据） */
    bool          is_server;
    bool          is_close;
    bool          handshake_done;
};

/* ========== SecureTransport I/O 回调 ========== */

static OSStatus
st_read_cb(SSLConnectionRef conn, void *data, size_t *len) {
    struct tls_context *c = (struct tls_context *)conn;
    size_t avail = buf_readable(&c->in_buf);
    if (avail == 0) { *len = 0; return errSSLWouldBlock; }
    size_t n = buf_read(&c->in_buf, data, *len);
    if (n < *len) { *len = n; return errSSLWouldBlock; }
    return noErr;
}

static OSStatus
st_write_cb(SSLConnectionRef conn, const void *data, size_t *len) {
    struct tls_context *c = (struct tls_context *)conn;
    if (!buf_write(&c->out_buf, data, *len)) return errSSLInternal;
    return noErr;
}

/* ========== 辅助函数 ========== */

static struct ssl_ctx *
_check_sslctx(lua_State *L, int idx) {
    struct ssl_ctx *p = (struct ssl_ctx *)lua_touserdata(L, idx);
    if (!p) luaL_error(L, "need sslctx");
    return p;
}

static struct tls_context *
_check_context(lua_State *L, int idx) {
    struct tls_context *p = (struct tls_context *)lua_touserdata(L, idx);
    if (!p) luaL_error(L, "need tls context");
    if (p->is_close) luaL_error(L, "context is closed");
    return p;
}

/* 将 out_buf 全部推入 Lua 栈 */
static int
flush_out(lua_State *L, struct tls_context *c) {
    size_t n = buf_readable(&c->out_buf);
    if (n == 0) return 0;
    lua_pushlstring(L, (const char *)(c->out_buf.data + c->out_buf.rpos), n);
    c->out_buf.len = c->out_buf.rpos = 0;
    return 1;
}

/* ========== ctx:set_cert 实现 ========== */

static int
_lctx_cert(lua_State *L) {
    struct ssl_ctx *ctx_p = _check_sslctx(L, 1);
    const char *certfile = lua_tostring(L, 2);
    const char *keyfile  = lua_tostring(L, 3);
    if (!certfile) luaL_error(L, "need certfile");
    if (!keyfile)  luaL_error(L, "need private key file");

    /* 读取证书文件 */
    FILE *f = fopen(certfile, "rb");
    if (!f) return luaL_error(L, "cannot open cert file: %s", certfile);
    fseek(f, 0, SEEK_END); long clen = ftell(f); fseek(f, 0, SEEK_SET);
    void *cbuf = malloc((size_t)clen);
    if (!cbuf) { fclose(f); return luaL_error(L, "out of memory"); }
    fread(cbuf, 1, (size_t)clen, f); fclose(f);

    /* 读取私钥文件 */
    f = fopen(keyfile, "rb");
    if (!f) { free(cbuf); return luaL_error(L, "cannot open key file: %s", keyfile); }
    fseek(f, 0, SEEK_END); long klen = ftell(f); fseek(f, 0, SEEK_SET);
    void *kbuf = malloc((size_t)klen);
    if (!kbuf) { free(cbuf); fclose(f); return luaL_error(L, "out of memory"); }
    fread(kbuf, 1, (size_t)klen, f); fclose(f);

    CFDataRef cert_data = CFDataCreate(NULL, (const UInt8 *)cbuf, (CFIndex)clen);
    CFDataRef key_data  = CFDataCreate(NULL, (const UInt8 *)kbuf, (CFIndex)klen);
    free(cbuf); free(kbuf);

    /*
     * SecIdentityRef 要求私钥存在于 keychain 中。
     * 使用临时 keychain 文件导入后取得 identity，再删除文件。
     * identity 持有对 keychain 内容的引用，删除文件后仍然有效。
     */
    char tmppath[256];
    snprintf(tmppath, sizeof(tmppath), "/tmp/luatask_tls_%d.keychain", (int)getpid());
    unlink(tmppath); /* 清理残留 */

    SecKeychainRef kc = NULL;
    OSStatus st = SecKeychainCreate(tmppath, 8, "luatask!", FALSE, NULL, &kc);
    if (st != noErr) {
        CFRelease(cert_data); CFRelease(key_data);
        return luaL_error(L, "SecKeychainCreate failed: %d", (int)st);
    }

    /* 导入证书 PEM */
    CFArrayRef cert_items = NULL;
    SecExternalFormat cert_fmt  = kSecFormatPEMSequence;
    SecExternalItemType cert_type = kSecItemTypeCertificate;
    st = SecItemImport(cert_data, NULL, &cert_fmt, &cert_type, 0, NULL, kc, &cert_items);
    CFRelease(cert_data);
    if (st != noErr || !cert_items || CFArrayGetCount(cert_items) == 0) {
        if (cert_items) CFRelease(cert_items);
        CFRelease(key_data);
        SecKeychainDelete(kc); CFRelease(kc); unlink(tmppath);
        return luaL_error(L, "failed to import certificate (PEM): %d", (int)st);
    }

    /* 导入私钥 PEM */
    CFArrayRef key_items = NULL;
    SecExternalFormat key_fmt  = kSecFormatPEMSequence;
    SecExternalItemType key_type = kSecItemTypePrivateKey;
    SecItemImportExportKeyParameters kparams;
    memset(&kparams, 0, sizeof(kparams));
    kparams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    st = SecItemImport(key_data, NULL, &key_fmt, &key_type, 0, &kparams, kc, &key_items);
    CFRelease(key_data);
    if (st != noErr || !key_items) {
        if (key_items) CFRelease(key_items);
        CFRelease(cert_items);
        SecKeychainDelete(kc); CFRelease(kc); unlink(tmppath);
        return luaL_error(L, "failed to import private key (PEM): %d", (int)st);
    }
    CFRelease(key_items);

    /* 根据证书查找 identity（cert + matching key） */
    SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(cert_items, 0);
    SecIdentityRef identity = NULL;
    st = SecIdentityCreateWithCertificate(kc, cert, &identity);
    CFRelease(cert_items);

    SecKeychainDelete(kc);
    CFRelease(kc);
    unlink(tmppath);

    if (st != noErr || !identity) {
        if (identity) CFRelease(identity);
        return luaL_error(L, "SecIdentityCreateWithCertificate failed: %d", (int)st);
    }

    if (ctx_p->identity) CFRelease(ctx_p->identity);
    ctx_p->identity = identity;
    return 0;
}

/* ========== ctx:__gc 实现 ========== */

static int
_lctx_gc(lua_State *L) {
    struct ssl_ctx *p = (struct ssl_ctx *)lua_touserdata(L, 1);
    if (p && p->identity) { CFRelease(p->identity); p->identity = NULL; }
    return 0;
}

/* ========== tls.newctx 实现 ========== */

static int
lnew_ctx(lua_State *L) {
    struct ssl_ctx *p = (struct ssl_ctx *)lua_newuserdatauv(L, sizeof(*p), 0);
    memset(p, 0, sizeof(*p));
    if (luaL_newmetatable(L, "_TLS_SSLCTX_METATABLE_")) {
        luaL_Reg l[] = { {"set_cert", _lctx_cert}, {NULL, NULL} };
        luaL_newlib(L, l);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, _lctx_gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    return 1;
}

/* ========== context:finished 实现 ========== */

static int
_ltls_context_finished(lua_State *L) {
    struct tls_context *p = _check_context(L, 1);
    lua_pushboolean(L, p->handshake_done);
    return 1;
}

/* ========== context:close 实现 ========== */

static int
_ltls_context_close(lua_State *L) {
    struct tls_context *p = (struct tls_context *)lua_touserdata(L, 1);
    if (!p || p->is_close) return 0;
    if (p->ssl) { CFRelease(p->ssl); p->ssl = NULL; }
    buf_free(&p->in_buf);
    buf_free(&p->out_buf);
    p->is_close = true;
    return 0;
}

/* ========== context:handshake 实现 ========== */

static int
_ltls_context_handshake(lua_State *L) {
    struct tls_context *p = _check_context(L, 1);
    size_t slen = 0;
    const char *data = lua_tolstring(L, 2, &slen);

    if (p->handshake_done) return luaL_error(L, "handshake is finished");

    if (slen > 0 && data)
        buf_write(&p->in_buf, data, slen);

    OSStatus st = SSLHandshake(p->ssl);
    if (st == noErr) {
        p->handshake_done = true;
        return flush_out(L, p);
    }
    if (st == errSSLWouldBlock) {
        return flush_out(L, p);
    }
    return luaL_error(L, "SSLHandshake failed: %d", (int)st);
}

/* ========== context:read 实现 ========== */

static int
_ltls_context_read(lua_State *L) {
    struct tls_context *p = _check_context(L, 1);
    size_t slen = 0;
    const char *enc = lua_tolstring(L, 2, &slen);

    if (slen > 0 && enc)
        buf_write(&p->in_buf, enc, slen);

    luaL_Buffer b;
    luaL_buffinit(L, &b);
    char tmp[4096];
    for (;;) {
        size_t processed = 0;
        OSStatus st = SSLRead(p->ssl, tmp, sizeof(tmp), &processed);
        if (processed > 0) luaL_addlstring(&b, tmp, processed);
        if (st == noErr) continue;
        /* errSSLWouldBlock / errSSLClosedGraceful / 其他错误：退出循环 */
        break;
    }
    luaL_pushresult(&b);
    return 1;
}

/* ========== context:write 实现 ========== */

static int
_ltls_context_write(lua_State *L) {
    struct tls_context *p = _check_context(L, 1);
    size_t slen = 0;
    const char *plain = lua_tolstring(L, 2, &slen);

    if (!plain || slen == 0) { lua_pushstring(L, ""); return 1; }

    size_t written = 0;
    OSStatus st = SSLWrite(p->ssl, plain, slen, &written);
    if (st != noErr && st != errSSLWouldBlock)
        return luaL_error(L, "SSLWrite failed: %d", (int)st);

    return flush_out(L, p);
}

/* ========== tls.newtls 实现 ========== */

static int
lnew_tls(lua_State *L) {
    const char *method = luaL_checkstring(L, 1);
    struct ssl_ctx *ctx_p = _check_sslctx(L, 2);

    bool is_server;
    if (strcmp(method, "client") == 0)      is_server = false;
    else if (strcmp(method, "server") == 0) is_server = true;
    else return luaL_error(L, "invalid method: %s e.g[server, client]", method);

    struct tls_context *p = (struct tls_context *)lua_newuserdatauv(L, sizeof(*p), 1);
    memset(p, 0, sizeof(*p));

    if (!buf_init(&p->in_buf) || !buf_init(&p->out_buf)) {
        buf_free(&p->in_buf); buf_free(&p->out_buf);
        return luaL_error(L, "out of memory");
    }

    p->is_server = is_server;

    p->ssl = SSLCreateContext(NULL,
        is_server ? kSSLServerSide : kSSLClientSide,
        kSSLStreamType);
    if (!p->ssl) {
        buf_free(&p->in_buf); buf_free(&p->out_buf);
        return luaL_error(L, "SSLCreateContext failed");
    }

    SSLSetIOFuncs(p->ssl, st_read_cb, st_write_cb);
    SSLSetConnection(p->ssl, (SSLConnectionRef)p);

    if (!is_server) {
        /* 客户端：设置 SNI，使用系统根证书自动验证 */
        if (!lua_isnoneornil(L, 3)) {
            const char *hostname = luaL_checkstring(L, 3);
            SSLSetPeerDomainName(p->ssl, hostname, strlen(hostname));
        }
    } else {
        /* 服务端：设置证书 identity */
        if (ctx_p->identity) {
            CFMutableArrayRef certs = CFArrayCreateMutable(NULL, 1, &kCFTypeArrayCallBacks);
            CFArrayAppendValue(certs, ctx_p->identity);
            OSStatus st = SSLSetCertificate(p->ssl, certs);
            CFRelease(certs);
            if (st != noErr) {
                CFRelease(p->ssl);
                buf_free(&p->in_buf); buf_free(&p->out_buf);
                return luaL_error(L, "SSLSetCertificate failed: %d", (int)st);
            }
        }
    }

    /* 保存 ctx 引用，防止 GC */
    lua_pushvalue(L, 2);
    lua_setiuservalue(L, -2, 1);

    if (luaL_newmetatable(L, "_TLS_CONTEXT_METATABLE_")) {
        luaL_Reg l[] = {
            {"close",     _ltls_context_close},
            {"finished",  _ltls_context_finished},
            {"handshake", _ltls_context_handshake},
            {"read",      _ltls_context_read},
            {"write",     _ltls_context_write},
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
int luaopen_tls(lua_State *L) {
    luaL_Reg l[] = {
        {"newctx", lnew_ctx},
        {"newtls", lnew_tls},
        {NULL, NULL},
    };
    luaL_checkversion(L);
    luaL_newlib(L, l);
    return 1;
}

#pragma clang diagnostic pop
