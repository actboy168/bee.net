package.path = package.path .. ";coroutine/?.lua"

local net = require "net"

local PORT = 12306

local function server_thread()
    local severfd = assert(net.listen("tcp", "127.0.0.1", PORT))
    while true do
        local clientfd = assert(severfd:accept())
        net.fork(function ()
            while true do
                local data = clientfd:recv(4)
                print("server recv: "..data)
                if data == "PING" then
                    clientfd:send "PONG"
                elseif data == "QUIT" then
                    clientfd:close()
                    return
                end
            end
        end)
        return
    end
end

local function client_thread()
    local clientfd = assert(net.connect("tcp", "127.0.0.1", PORT))
    for _ = 1, 4 do
        clientfd:send "PING"
        assert(clientfd:recv(4) == "PONG")
        print "client recv: PONG"
    end
    clientfd:send "QUIT"
    clientfd:close()
end

net.fork(server_thread)
net.fork(client_thread)

while net.schedule() do
    net.wait(1)
end
