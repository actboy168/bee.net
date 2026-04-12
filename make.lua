local lm = require "luamake"

lm:lua_dll "tls" {
    windows = {
        sources = "tls/tls_windows.c",
        links = { "secur32", "crypt32", "bcrypt", "ncrypt" }
    },
    linux = {
        sources = "tls/tls_openssl.c",
        links = { "ssl", "crypto" }
    },
    macos = {
        sources = "tls/tls_macos.c",
        frameworks = { "Security", "CoreFoundation" },
    },
}
