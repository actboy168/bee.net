-- bench.lua: 连续发起 N 次并发 HTTP 请求，测量总耗时
local N = tonumber(arg and arg[1]) or 20

package.cpath = "./../../bee.lua/build/bin/?.so;./../build/bin/?.so"
package.path  = "./?.lua;./http/?.lua"

local socket = require "bee.socket"
local net    = require "net"
local httpc  = require "http.httpc"

-- 使用 bee.socket 的高精度时钟（如有），否则退回 os.time
local function now_ms()
    -- bee.time 提供高精度时间
    local ok, t = pcall(require, "bee.time")
    if ok then
        now_ms = function() return t.monotonic() end
        return t.monotonic()
    end
    now_ms = function() return os.time() * 1000 end
    return os.time() * 1000
end

local done  = 0
local t0    = now_ms()

for i = 1, N do
    net.fork(function()
        local ok, err = pcall(function()
            httpc.request("GET", "https://www.baidu.com", "/")
        end)
        done = done + 1
        if not ok then
            io.stderr:write("request " .. i .. " failed: " .. tostring(err) .. "\n")
        end
    end)
end

while net.schedule() do
    net.wait(1)
    if done == N then break end
end

local elapsed_ms = now_ms() - t0
print(string.format("N=%d  elapsed=%.0fms  avg=%.1fms/req",
    N, elapsed_ms, elapsed_ms / N))
