local lm = require "luamake"

lm:lua_dll "tls" {
    luaversion = "lua55",
    sources = {
        "tls/tls.c",
    },
    links = {
        "secur32",
        "crypt32",
        "bcrypt",
        "ncrypt",
    },
}
