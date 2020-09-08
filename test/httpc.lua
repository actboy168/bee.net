local httpc = require "http.httpc"
local respheader = {}
local status, body = httpc.get("http://www.baidu.com", "/", respheader)
print(status, body)
