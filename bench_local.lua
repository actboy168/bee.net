-- bench_local.lua: 本地 echo server 吞吐测试
-- 每个连接发送一大块数据，接收回来，测量吞吐
local N_CONN  = 10
local N_MSGS  = 50
local MSG     = ("x"):rep(4096)  -- 4KB，匹配缓冲区大小

package.cpath = "./../../bee.lua/build/bin/?.so;./../build/bin/?.so"
package.path  = "./?.lua;./http/?.lua"

local net = require "net"

local ok, bee_time = pcall(require, "bee.time")
local function now_ms()
    if ok then return bee_time.monotonic() end
    return os.time() * 1000
end

local t0
local done = 0

net.fork(function()
    local server = net.listen("tcp", "127.0.0.1", 19999)
    assert(server, "listen failed")

    net.fork(function()
        for _ = 1, N_CONN do
            local fd = server:accept()
            net.fork(function()
                while true do
                    local data = fd:recv()
                    if not data then break end
                    fd:send(data)
                end
                fd:close()
            end)
        end
        server:close()
    end)

    net.yield()
    t0 = now_ms()

    for _ = 1, N_CONN do
        net.fork(function()
            local fd = net.connect("tcp", "127.0.0.1", 19999)
            assert(fd, "connect failed")
            local received = 0
            local expected = N_MSGS * #MSG
            -- 提交所有发送
            for _ = 1, N_MSGS do
                fd:send(MSG)
            end
            -- 接收直到拿够
            while received < expected do
                local r = fd:recv()
                if not r then break end
                received = received + #r
            end
            fd:close()
            done = done + 1
        end)
    end
end)

while net.schedule() do
    net.wait(1)
    if done == N_CONN then break end
end

local elapsed = now_ms() - t0
local total_bytes = N_CONN * N_MSGS * #MSG * 2
print(string.format(
    "conns=%d msgs/conn=%d msg_size=%dB  elapsed=%dms  throughput=%.1fMB/s",
    N_CONN, N_MSGS, #MSG, elapsed,
    total_bytes / elapsed / 1000
))
