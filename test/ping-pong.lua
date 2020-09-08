local net = require "net"

local PORT = 12306

local server = assert(net.listen("tcp", "127.0.0.1", PORT))
function server:on_accept(s)
    print "[Listen][accept]"
    s:write "Ping"
    function s:on_data(data)
        print("[Server][data]", data)
        --self:write "Ping"
    end
    function s:on_close()
        print "[Server][close]"
    end
    function s:on_error(...)
        print("[Server][error]", ...)
    end
end
function server:on_close()
    print "[Listen][close]"
end
function server:on_error(...)
    print("[Listen][error]", ...)
end

local client = assert(net.connect("tcp", "127.0.0.1", PORT))
function client:on_connect()
    print("[Client][connect]")
end
function client:on_data(data)
    print("[Client][data]", data)
    self:write "Pong"
    self:close()
end
function client:on_close()
    print "[Client][close]"
end
function client:on_error(...)
    print("[Client][error]", ...)
end

while true do
    net.update()
end
