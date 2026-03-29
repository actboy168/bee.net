local lm = require "luamake"

lm:lua_dll "tls" {
    luaversion = "lua55",
    sources = {
        lm.os == "windows"
            and "tls/tls_windows.c" 
            or "tls/tls_openssl.c",
    },
    links = lm.os == "windows"
        and { "secur32", "crypt32", "bcrypt", "ncrypt" }
        or  { "ssl", "crypto" },
}
