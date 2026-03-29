local net = require "net"
local httpc = require "http.httpc"

net.fork(function()
    local respheader = {}
    local status, body = httpc.request("GET", "https://www.baidu.com", "/", respheader)
    print(status, body)
end)

while net.schedule() do
    net.wait(1)
end
