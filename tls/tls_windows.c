/*
 * tls.c - TLS 模块，基于 Windows SChannel/SSPI 实现
 * 提供与 skynet ltls.c 兼容的 Lua 接口
 */

#define SECURITY_WIN32

#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

/* 链接所需的系统库 */
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

/* ========== 初始接收缓冲区大小 ========== */
#define INIT_RECV_BUF_SIZE 16384

/* ========== 结构体定义 ========== */

/* TLS 上下文（对应 SChannel 凭据） */
struct ssl_ctx {
    CredHandle cred_handle;       /* SChannel 凭据句柄 */
    bool is_initialized;          /* 凭据是否已初始化 */
    HCERTSTORE cert_store;        /* 证书存储（服务端模式用） */
    PCCERT_CONTEXT cert_context;  /* 证书上下文（服务端模式用） */
};

/* TLS 连接对象 */
struct tls_context {
    CtxtHandle sec_context;       /* SSPI 安全上下文 */
    CredHandle* cred_handle;      /* 指向 ssl_ctx 的凭据句柄 */
    bool is_server;               /* 是否为服务端模式 */
    bool is_close;                /* 是否已关闭 */
    bool handshake_done;          /* 握手是否完成 */
    bool context_initialized;     /* 安全上下文是否已初始化（首次握手后为 true） */
    char hostname[256];           /* 服务器主机名（客户端 SNI 用） */
    char* recv_buf;               /* 接收缓冲区 */
    size_t recv_len;              /* 缓冲区中已有数据长度 */
    size_t recv_cap;              /* 缓冲区容量 */
    SecPkgContext_StreamSizes stream_sizes; /* 流大小信息（握手完成后查询） */
    bool stream_sizes_queried;    /* 是否已查询流大小 */
};

/* ========== 错误处理辅助函数 ========== */

static void
_format_sspi_error(lua_State* L, const char* func_name, SECURITY_STATUS ss) {
    char msg[512];
    char desc[256];
    DWORD ret = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)ss, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
        desc, sizeof(desc), NULL);
    if (ret > 0) {
        /* 去掉末尾换行 */
        while (ret > 0 && (desc[ret-1] == '\n' || desc[ret-1] == '\r'))
            desc[--ret] = '\0';
        snprintf(msg, sizeof(msg), "%s failed: 0x%08X (%s)", func_name, (unsigned int)ss, desc);
    } else {
        snprintf(msg, sizeof(msg), "%s failed: 0x%08X", func_name, (unsigned int)ss);
    }
    luaL_error(L, msg);
}

/* ========== 缓冲区辅助函数 ========== */

static void
_ensure_recv_buf(struct tls_context* tls_p, size_t additional) {
    size_t needed = tls_p->recv_len + additional;
    if (needed <= tls_p->recv_cap)
        return;
    size_t new_cap = tls_p->recv_cap * 2;
    if (new_cap < needed)
        new_cap = needed;
    char* new_buf = (char*)realloc(tls_p->recv_buf, new_cap);
    if (!new_buf) return;
    tls_p->recv_buf = new_buf;
    tls_p->recv_cap = new_cap;
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

/* ========== 查询流大小信息 ========== */

static void
_query_stream_sizes(lua_State* L, struct tls_context* tls_p) {
    if (tls_p->stream_sizes_queried)
        return;
    SECURITY_STATUS ss = QueryContextAttributes(
        &tls_p->sec_context, SECPKG_ATTR_STREAM_SIZES, &tls_p->stream_sizes);
    if (ss != SEC_E_OK) {
        _format_sspi_error(L, "QueryContextAttributes(STREAM_SIZES)", ss);
    }
    tls_p->stream_sizes_queried = true;
}

/* ========== PEM 文件读取辅助函数 ========== */

/* 读取文件全部内容到内存 */
static char*
_read_file_content(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) { fclose(f); return NULL; }
    char* buf = (char*)malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t read = fread(buf, 1, len, f);
    fclose(f);
    buf[read] = '\0';
    *out_len = read;
    return buf;
}

/* 从 PEM 内容中提取 Base64 编码的 DER 数据 */
static BYTE*
_pem_to_der(const char* pem_data, size_t pem_len, DWORD* out_der_len) {
    /* 使用 CryptStringToBinaryA 解码 PEM */
    DWORD der_len = 0;
    if (!CryptStringToBinaryA(pem_data, (DWORD)pem_len,
            CRYPT_STRING_BASE64HEADER, NULL, &der_len, NULL, NULL)) {
        return NULL;
    }
    BYTE* der_buf = (BYTE*)malloc(der_len);
    if (!der_buf) return NULL;
    if (!CryptStringToBinaryA(pem_data, (DWORD)pem_len,
            CRYPT_STRING_BASE64HEADER, der_buf, &der_len, NULL, NULL)) {
        free(der_buf);
        return NULL;
    }
    *out_der_len = der_len;
    return der_buf;
}

/* ========== ctx:set_cert 实现 ========== */

static int
_lctx_cert(lua_State* L) {
    struct ssl_ctx* ctx_p = _check_sslctx(L, 1);
    const char* certfile = lua_tostring(L, 2);
    const char* keyfile = lua_tostring(L, 3);
    if (!certfile) luaL_error(L, "need certfile");
    if (!keyfile) luaL_error(L, "need private key file");

    /* 1. 读取并解码证书 PEM 文件 */
    size_t cert_pem_len = 0;
    char* cert_pem = _read_file_content(certfile, &cert_pem_len);
    if (!cert_pem) luaL_error(L, "cannot read cert file: %s", certfile);

    DWORD cert_der_len = 0;
    BYTE* cert_der = _pem_to_der(cert_pem, cert_pem_len, &cert_der_len);
    free(cert_pem);
    if (!cert_der) luaL_error(L, "failed to decode cert PEM: %s", certfile);

    /* 2. 创建证书上下文 */
    PCCERT_CONTEXT cert_ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_der, cert_der_len);
    free(cert_der);
    if (!cert_ctx) luaL_error(L, "CertCreateCertificateContext failed: 0x%08X", GetLastError());

    /* 3. 读取并解码私钥 PEM 文件 */
    size_t key_pem_len = 0;
    char* key_pem = _read_file_content(keyfile, &key_pem_len);
    if (!key_pem) {
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "cannot read key file: %s", keyfile);
    }

    DWORD key_der_len = 0;
    BYTE* key_der = _pem_to_der(key_pem, key_pem_len, &key_der_len);
    free(key_pem);
    if (!key_der) {
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "failed to decode key PEM: %s", keyfile);
    }

    /* 4. 使用 CNG 导入私钥并关联到证书 */
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS ss;

    ss = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (ss != ERROR_SUCCESS) {
        free(key_der);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "NCryptOpenStorageProvider failed: 0x%08X", (unsigned int)ss);
    }

    /* 解码私钥 DER 为 BCRYPT_RSAKEY_BLOB */
    DWORD rsa_key_len = 0;
    BYTE* rsa_key_blob = NULL;

    /* 尝试 PKCS#8 私钥信息格式 */
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_RSA_PRIVATE_KEY, key_der, key_der_len,
            CRYPT_DECODE_ALLOC_FLAG, NULL, &rsa_key_blob, &rsa_key_len)) {
        /* 尝试 PKCS#8 包装格式 */
        DWORD pk8_len = 0;
        BYTE* pk8_info = NULL;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                PKCS_PRIVATE_KEY_INFO, key_der, key_der_len,
                CRYPT_DECODE_ALLOC_FLAG, NULL, &pk8_info, &pk8_len)) {
            CRYPT_PRIVATE_KEY_INFO* pki = (CRYPT_PRIVATE_KEY_INFO*)pk8_info;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    PKCS_RSA_PRIVATE_KEY,
                    pki->PrivateKey.pbData, pki->PrivateKey.cbData,
                    CRYPT_DECODE_ALLOC_FLAG, NULL, &rsa_key_blob, &rsa_key_len)) {
                LocalFree(pk8_info);
                free(key_der);
                NCryptFreeObject(hProv);
                CertFreeCertificateContext(cert_ctx);
                luaL_error(L, "CryptDecodeObjectEx(RSA_PRIVATE_KEY from PKCS8) failed: 0x%08X", GetLastError());
            }
            LocalFree(pk8_info);
        } else {
            free(key_der);
            NCryptFreeObject(hProv);
            CertFreeCertificateContext(cert_ctx);
            luaL_error(L, "CryptDecodeObjectEx(PRIVATE_KEY) failed: 0x%08X", GetLastError());
        }
    }
    free(key_der);

    /* 导入 RSA 私钥到 CNG */
    /* 先将 CAPI RSA blob 转为 CNG blob */
    BCRYPT_KEY_HANDLE hBcryptKey = 0;
    BCRYPT_ALG_HANDLE hAlg = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0) {
        LocalFree(rsa_key_blob);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "BCryptOpenAlgorithmProvider failed");
    }

    /* 使用 legacy blob 导入 */
    NTSTATUS status = BCryptImportKeyPair(hAlg, NULL, LEGACY_RSAPRIVATE_BLOB,
        &hBcryptKey, rsa_key_blob, rsa_key_len, 0);
    LocalFree(rsa_key_blob);

    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "BCryptImportKeyPair failed: 0x%08X", (unsigned int)status);
    }

    /* 导出为 CNG blob */
    DWORD cng_blob_len = 0;
    BCryptExportKey(hBcryptKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &cng_blob_len, 0);
    BYTE* cng_blob = (BYTE*)malloc(cng_blob_len);
    status = BCryptExportKey(hBcryptKey, NULL, BCRYPT_RSAPRIVATE_BLOB, cng_blob, cng_blob_len, &cng_blob_len, 0);
    BCryptDestroyKey(hBcryptKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != 0) {
        free(cng_blob);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "BCryptExportKey failed: 0x%08X", (unsigned int)status);
    }

    /* 导入到 NCrypt */
    ss = NCryptImportKey(hProv, 0, BCRYPT_RSAPRIVATE_BLOB, NULL,
        &hKey, cng_blob, cng_blob_len, NCRYPT_OVERWRITE_KEY_FLAG);
    free(cng_blob);

    if (ss != ERROR_SUCCESS) {
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "NCryptImportKey failed: 0x%08X", (unsigned int)ss);
    }

    /* 6. 将私钥关联到证书 */
    CRYPT_KEY_PROV_INFO kpi;
    memset(&kpi, 0, sizeof(kpi));
    kpi.pwszContainerName = L"TlsTempKey";
    kpi.pwszProvName = MS_KEY_STORAGE_PROVIDER;
    kpi.dwProvType = 0;
    kpi.dwKeySpec = 0;

    if (!CertSetCertificateContextProperty(cert_ctx,
            CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "CertSetCertificateContextProperty failed: 0x%08X", GetLastError());
    }

    /* 也设置 NCRYPT_KEY_HANDLE 属性 */
    if (!CertSetCertificateContextProperty(cert_ctx,
            CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, &hKey)) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "CertSetCertificateContextProperty(NCRYPT_KEY) failed: 0x%08X", GetLastError());
    }

    /* 7. 创建内存证书存储并添加证书 */
    if (ctx_p->cert_store) {
        CertCloseStore(ctx_p->cert_store, 0);
    }
    ctx_p->cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
        CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!ctx_p->cert_store) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "CertOpenStore failed: 0x%08X", GetLastError());
    }

    if (!CertAddCertificateContextToStore(ctx_p->cert_store, cert_ctx,
            CERT_STORE_ADD_REPLACE_EXISTING, &ctx_p->cert_context)) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(cert_ctx);
        luaL_error(L, "CertAddCertificateContextToStore failed: 0x%08X", GetLastError());
    }
    CertFreeCertificateContext(cert_ctx);

    /* 8. 释放旧凭据，使用证书重新获取凭据（服务端模式） */
    if (ctx_p->is_initialized) {
        FreeCredentialsHandle(&ctx_p->cred_handle);
        ctx_p->is_initialized = false;
    }

    SCHANNEL_CRED schannel_cred;
    memset(&schannel_cred, 0, sizeof(schannel_cred));
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.cCreds = 1;
    schannel_cred.paCred = &ctx_p->cert_context;
    schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    schannel_cred.dwFlags = 0;

    TimeStamp ts;
    ss = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_INBOUND,
        NULL, &schannel_cred, NULL, NULL, &ctx_p->cred_handle, &ts);
    if (ss != SEC_E_OK) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        _format_sspi_error(L, "AcquireCredentialsHandle(INBOUND with cert)", ss);
    }
    ctx_p->is_initialized = true;

    NCryptFreeObject(hKey);
    NCryptFreeObject(hProv);
    return 0;
}

/* ========== ctx:__gc 实现 ========== */

static int
_lctx_gc(lua_State* L) {
    struct ssl_ctx* ctx_p = (struct ssl_ctx*)lua_touserdata(L, 1);
    if (!ctx_p) return 0;
    if (ctx_p->is_initialized) {
        FreeCredentialsHandle(&ctx_p->cred_handle);
        ctx_p->is_initialized = false;
    }
    if (ctx_p->cert_context) {
        CertFreeCertificateContext(ctx_p->cert_context);
        ctx_p->cert_context = NULL;
    }
    if (ctx_p->cert_store) {
        CertCloseStore(ctx_p->cert_store, 0);
        ctx_p->cert_store = NULL;
    }
    return 0;
}

/* ========== tls.newctx 实现 ========== */

static int
lnew_ctx(lua_State* L) {
    struct ssl_ctx* ctx_p = (struct ssl_ctx*)lua_newuserdatauv(L, sizeof(*ctx_p), 0);
    memset(ctx_p, 0, sizeof(*ctx_p));

    /* 配置 SCHANNEL_CRED，默认客户端模式（无证书） */
    SCHANNEL_CRED schannel_cred;
    memset(&schannel_cred, 0, sizeof(schannel_cred));
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    schannel_cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION |
                            SCH_CRED_NO_DEFAULT_CREDS |
                            SCH_USE_STRONG_CRYPTO;

    TimeStamp ts;
    SECURITY_STATUS ss = AcquireCredentialsHandle(
        NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
        NULL, &schannel_cred, NULL, NULL,
        &ctx_p->cred_handle, &ts);
    if (ss != SEC_E_OK) {
        _format_sspi_error(L, "AcquireCredentialsHandle", ss);
    }
    ctx_p->is_initialized = true;

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
        if (tls_p->context_initialized) {
            DeleteSecurityContext(&tls_p->sec_context);
            tls_p->context_initialized = false;
        }
        if (tls_p->recv_buf) {
            free(tls_p->recv_buf);
            tls_p->recv_buf = NULL;
        }
        tls_p->recv_len = 0;
        tls_p->recv_cap = 0;
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
        luaL_error(L, "handshake is finished");
    }

    /* 将收到的数据追加到接收缓冲区 */
    if (slen > 0 && exchange != NULL) {
        _ensure_recv_buf(tls_p, slen);
        memcpy(tls_p->recv_buf + tls_p->recv_len, exchange, slen);
        tls_p->recv_len += slen;
    }

    SECURITY_STATUS ss;

    if (!tls_p->is_server) {
        /* ===== 客户端握手 ===== */
        DWORD flags = ISC_REQ_SEQUENCE_DETECT |
                      ISC_REQ_REPLAY_DETECT |
                      ISC_REQ_CONFIDENTIALITY |
                      ISC_REQ_EXTENDED_ERROR |
                      ISC_REQ_ALLOCATE_MEMORY |
                      ISC_REQ_STREAM;

        SecBuffer out_buf;
        out_buf.cbBuffer = 0;
        out_buf.BufferType = SECBUFFER_TOKEN;
        out_buf.pvBuffer = NULL;

        SecBufferDesc out_desc;
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out_buf;

        DWORD out_flags = 0;

        /* 将 hostname 转为宽字符用于 SNI */
        SEC_WCHAR w_hostname[256];
        MultiByteToWideChar(CP_UTF8, 0, tls_p->hostname, -1, w_hostname, 256);

        if (!tls_p->context_initialized) {
            /* 首次调用：生成 ClientHello */
            ss = InitializeSecurityContextW(
                tls_p->cred_handle,
                NULL,                   /* 首次调用传 NULL */
                w_hostname,             /* 目标名称（SNI） */
                flags,
                0,                      /* Reserved1 */
                0,                      /* TargetDataRep */
                NULL,                   /* 首次调用无输入 */
                0,                      /* Reserved2 */
                &tls_p->sec_context,    /* 输出：新的安全上下文 */
                &out_desc,
                &out_flags,
                NULL);

            if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_OK) {
                tls_p->context_initialized = true;
            }
        } else {
            /* 后续调用：传入服务端响应数据 */
            SecBuffer in_bufs[2];
            in_bufs[0].cbBuffer = (unsigned long)tls_p->recv_len;
            in_bufs[0].BufferType = SECBUFFER_TOKEN;
            in_bufs[0].pvBuffer = tls_p->recv_buf;
            in_bufs[1].cbBuffer = 0;
            in_bufs[1].BufferType = SECBUFFER_EMPTY;
            in_bufs[1].pvBuffer = NULL;

            SecBufferDesc in_desc;
            in_desc.ulVersion = SECBUFFER_VERSION;
            in_desc.cBuffers = 2;
            in_desc.pBuffers = in_bufs;

            ss = InitializeSecurityContextW(
                tls_p->cred_handle,
                &tls_p->sec_context,
                w_hostname,
                flags,
                0, 0,
                &in_desc,
                0,
                NULL,                   /* 已有上下文，不需要输出新上下文 */
                &out_desc,
                &out_flags,
                NULL);

            /* 处理 SECBUFFER_EXTRA：未消费的数据（仅在非 INCOMPLETE_MESSAGE 时） */
            if (ss != SEC_E_INCOMPLETE_MESSAGE) {
                if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
                    size_t extra = in_bufs[1].cbBuffer;
                    memmove(tls_p->recv_buf,
                            tls_p->recv_buf + tls_p->recv_len - extra,
                            extra);
                    tls_p->recv_len = extra;
                } else {
                    tls_p->recv_len = 0;
                }
            }
        }

        if (ss == SEC_E_OK) {
            tls_p->handshake_done = true;
            /* 返回最后的握手数据（如果有） */
            if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
                lua_pushlstring(L, (const char*)out_buf.pvBuffer, out_buf.cbBuffer);
                FreeContextBuffer(out_buf.pvBuffer);
                return 1;
            }
            return 0;
        } else if (ss == SEC_I_CONTINUE_NEEDED) {
            if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
                lua_pushlstring(L, (const char*)out_buf.pvBuffer, out_buf.cbBuffer);
                FreeContextBuffer(out_buf.pvBuffer);
                return 1;
            }
            return 0;
        } else if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            /* 需要更多数据，不消费缓冲区 */
            if (out_buf.pvBuffer) FreeContextBuffer(out_buf.pvBuffer);
            return 0;
        } else {
            if (out_buf.pvBuffer) FreeContextBuffer(out_buf.pvBuffer);
            _format_sspi_error(L, "InitializeSecurityContext", ss);
        }
    } else {
        /* ===== 服务端握手 ===== */
        DWORD flags = ASC_REQ_SEQUENCE_DETECT |
                      ASC_REQ_REPLAY_DETECT |
                      ASC_REQ_CONFIDENTIALITY |
                      ASC_REQ_EXTENDED_ERROR |
                      ASC_REQ_ALLOCATE_MEMORY |
                      ASC_REQ_STREAM;

        SecBuffer in_bufs[2];
        in_bufs[0].cbBuffer = (unsigned long)tls_p->recv_len;
        in_bufs[0].BufferType = SECBUFFER_TOKEN;
        in_bufs[0].pvBuffer = tls_p->recv_buf;
        in_bufs[1].cbBuffer = 0;
        in_bufs[1].BufferType = SECBUFFER_EMPTY;
        in_bufs[1].pvBuffer = NULL;

        SecBufferDesc in_desc;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_bufs;

        SecBuffer out_buf;
        out_buf.cbBuffer = 0;
        out_buf.BufferType = SECBUFFER_TOKEN;
        out_buf.pvBuffer = NULL;

        SecBufferDesc out_desc;
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out_buf;

        DWORD out_flags = 0;

        if (!tls_p->context_initialized) {
            ss = AcceptSecurityContext(
                tls_p->cred_handle,
                NULL,
                &in_desc,
                flags,
                0,
                &tls_p->sec_context,
                &out_desc,
                &out_flags,
                NULL);
            if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_OK) {
                tls_p->context_initialized = true;
            }
        } else {
            ss = AcceptSecurityContext(
                tls_p->cred_handle,
                &tls_p->sec_context,
                &in_desc,
                flags,
                0,
                NULL,
                &out_desc,
                &out_flags,
                NULL);
        }

        /* 处理 SECBUFFER_EXTRA（仅在非 INCOMPLETE_MESSAGE 时） */
        if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
                size_t extra = in_bufs[1].cbBuffer;
                memmove(tls_p->recv_buf,
                        tls_p->recv_buf + tls_p->recv_len - extra,
                        extra);
                tls_p->recv_len = extra;
            } else {
                tls_p->recv_len = 0;
            }
        }

        if (ss == SEC_E_OK) {
            tls_p->handshake_done = true;
            if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
                lua_pushlstring(L, (const char*)out_buf.pvBuffer, out_buf.cbBuffer);
                FreeContextBuffer(out_buf.pvBuffer);
                return 1;
            }
            return 0;
        } else if (ss == SEC_I_CONTINUE_NEEDED) {
            if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
                lua_pushlstring(L, (const char*)out_buf.pvBuffer, out_buf.cbBuffer);
                FreeContextBuffer(out_buf.pvBuffer);
                return 1;
            }
            return 0;
        } else if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            if (out_buf.pvBuffer) FreeContextBuffer(out_buf.pvBuffer);
            return 0;
        } else {
            if (out_buf.pvBuffer) FreeContextBuffer(out_buf.pvBuffer);
            _format_sspi_error(L, "AcceptSecurityContext", ss);
        }
    }

    return 0;
}

/* ========== tls_context:read 实现 ========== */

static int
_ltls_context_read(lua_State* L) {
    struct tls_context* tls_p = _check_context(L, 1);
    size_t slen = 0;
    const char* encrypted_data = lua_tolstring(L, 2, &slen);

    /* 将加密数据追加到接收缓冲区 */
    if (slen > 0 && encrypted_data) {
        _ensure_recv_buf(tls_p, slen);
        memcpy(tls_p->recv_buf + tls_p->recv_len, encrypted_data, slen);
        tls_p->recv_len += slen;
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    while (tls_p->recv_len > 0) {
        SecBuffer bufs[4];
        bufs[0].cbBuffer = (unsigned long)tls_p->recv_len;
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = tls_p->recv_buf;
        bufs[1].cbBuffer = 0;
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[1].pvBuffer = NULL;
        bufs[2].cbBuffer = 0;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[2].pvBuffer = NULL;
        bufs[3].cbBuffer = 0;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].pvBuffer = NULL;

        SecBufferDesc buf_desc;
        buf_desc.ulVersion = SECBUFFER_VERSION;
        buf_desc.cBuffers = 4;
        buf_desc.pBuffers = bufs;

        SECURITY_STATUS ss = DecryptMessage(&tls_p->sec_context, &buf_desc, 0, NULL);

        if (ss == SEC_E_OK) {
            /* 提取解密后的数据 */
            for (int i = 0; i < 4; i++) {
                if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                    luaL_addlstring(&b, (const char*)bufs[i].pvBuffer, bufs[i].cbBuffer);
                }
            }

            /* 处理 SECBUFFER_EXTRA：未消费的数据 */
            bool has_extra = false;
            for (int i = 0; i < 4; i++) {
                if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer > 0) {
                    size_t extra = bufs[i].cbBuffer;
                    memmove(tls_p->recv_buf,
                            tls_p->recv_buf + tls_p->recv_len - extra,
                            extra);
                    tls_p->recv_len = extra;
                    has_extra = true;
                    break;
                }
            }
            if (!has_extra) {
                tls_p->recv_len = 0;
            }
            /* 继续循环，尝试解密更多数据 */
        } else if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            /* 数据不完整，等待更多输入 */
            break;
        } else if (ss == SEC_I_RENEGOTIATE) {
            /* 重新协商，重置握手状态 */
            tls_p->handshake_done = false;
            tls_p->stream_sizes_queried = false;
            break;
        } else if (ss == SEC_I_CONTEXT_EXPIRED) {
            /* 连接已关闭 */
            break;
        } else {
            _format_sspi_error(L, "DecryptMessage", ss);
        }
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

    /* 确保已查询流大小 */
    _query_stream_sizes(L, tls_p);

    DWORD max_msg = tls_p->stream_sizes.cbMaximumMessage;
    DWORD header_size = tls_p->stream_sizes.cbHeader;
    DWORD trailer_size = tls_p->stream_sizes.cbTrailer;

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    const char* p = plain_data;
    size_t remaining = slen;

    while (remaining > 0) {
        DWORD chunk = (remaining > max_msg) ? max_msg : (DWORD)remaining;

        /* 分配缓冲区：header + data + trailer */
        DWORD buf_size = header_size + chunk + trailer_size;
        char* io_buf = (char*)malloc(buf_size);
        if (!io_buf) luaL_error(L, "out of memory in write");

        /* 复制明文到 data 区域 */
        memcpy(io_buf + header_size, p, chunk);

        SecBuffer bufs[4];
        bufs[0].cbBuffer = header_size;
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = io_buf;

        bufs[1].cbBuffer = chunk;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = io_buf + header_size;

        bufs[2].cbBuffer = trailer_size;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = io_buf + header_size + chunk;

        bufs[3].cbBuffer = 0;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        bufs[3].pvBuffer = NULL;

        SecBufferDesc buf_desc;
        buf_desc.ulVersion = SECBUFFER_VERSION;
        buf_desc.cBuffers = 4;
        buf_desc.pBuffers = bufs;

        SECURITY_STATUS ss = EncryptMessage(&tls_p->sec_context, 0, &buf_desc, 0);
        if (ss != SEC_E_OK) {
            free(io_buf);
            _format_sspi_error(L, "EncryptMessage", ss);
        }

        /* 拼接加密后的数据（header + data + trailer） */
        luaL_addlstring(&b, (const char*)bufs[0].pvBuffer, bufs[0].cbBuffer);
        luaL_addlstring(&b, (const char*)bufs[1].pvBuffer, bufs[1].cbBuffer);
        luaL_addlstring(&b, (const char*)bufs[2].pvBuffer, bufs[2].cbBuffer);

        free(io_buf);
        p += chunk;
        remaining -= chunk;
    }

    luaL_pushresult(&b);
    return 1;
}

/* ========== tls.newtls 实现 ========== */

static int
lnew_tls(lua_State* L) {
    const char* method = luaL_checkstring(L, 1);
    struct ssl_ctx* ctx_p = _check_sslctx(L, 2);

    struct tls_context* tls_p = (struct tls_context*)lua_newuserdatauv(L, sizeof(*tls_p), 1);
    memset(tls_p, 0, sizeof(*tls_p));

    tls_p->cred_handle = &ctx_p->cred_handle;
    tls_p->is_close = false;
    tls_p->handshake_done = false;
    tls_p->context_initialized = false;
    tls_p->stream_sizes_queried = false;

    /* 分配接收缓冲区 */
    tls_p->recv_buf = (char*)malloc(INIT_RECV_BUF_SIZE);
    if (!tls_p->recv_buf) luaL_error(L, "out of memory");
    tls_p->recv_len = 0;
    tls_p->recv_cap = INIT_RECV_BUF_SIZE;

    /* 保存 ctx 引用，防止 GC */
    lua_pushvalue(L, 2);
    lua_setiuservalue(L, -2, 1);

    if (strcmp(method, "client") == 0) {
        tls_p->is_server = false;
        /* 保存 hostname（用于 SNI） */
        if (!lua_isnoneornil(L, 3)) {
            const char* hostname = luaL_checkstring(L, 3);
            strncpy_s(tls_p->hostname, sizeof(tls_p->hostname), hostname, _TRUNCATE);
            tls_p->hostname[sizeof(tls_p->hostname) - 1] = '\0';
        }
    } else if (strcmp(method, "server") == 0) {
        tls_p->is_server = true;
    } else {
        luaL_error(L, "invalid method:%s e.g[server, client]", method);
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


