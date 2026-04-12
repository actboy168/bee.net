local ltask = require "ltask"
local socket = require "bee.socket"
local async = require "bee.async"

local asfd = async.create(512)

local SUCCESS <const> = async.SUCCESS

local kReadBufSize <const> = 64 * 1024  -- 上限 64KB，不预分配，循环 recv 直到 EAGAIN
local kReadPipeline <const> = 1          -- C++ 层已循环 recv，无需多个 in-flight

local status = {}
local handle = {}

local next_reqid = 1
local function alloc_reqid()
    local id = next_reqid
    next_reqid = id + 1
    return id
end

local pending = {}

local function create_handle(fd)
    local h = handle[fd]
    if h then
        return h
    end
    h = #handle + 1
    handle[h] = fd
    handle[fd] = h
    return h
end

local function close_stream(s)
    if s.closed then
        return
    end
    s.closed = true
    if s.wait_read then
        for i, token in ipairs(s.wait_read) do
            ltask.wakeup(token)
            s.wait_read[i] = nil
        end
    end
    if s.wait_write then
        for i, token in ipairs(s.wait_write) do
            ltask.interrupt(token, "Write close.")
            s.wait_write[i] = nil
        end
    end
    if s.wait_close then
        for _, token in ipairs(s.wait_close) do
            ltask.wakeup(token)
        end
        s.wait_close = nil
    end
    s.fd:close()
end

local function stream_submit_read(s)
    if s.closed then
        return
    end
    while s.read_in_flight < kReadPipeline do
        if #s.readbuf >= kReadBufSize * kReadPipeline then
            break  -- 背压：缓冲已满，停止补充
        end
        local reqid = alloc_reqid()
        s.read_in_flight = s.read_in_flight + 1
        pending[reqid] = { type = "read", s = s }
        asfd:submit_read(s.fd, kReadBufSize, reqid)
    end
end

local function stream_on_read(s, data)
    s.read_in_flight = s.read_in_flight - 1
    if data == nil then
        close_stream(s)
        return
    end
    s.readbuf = s.readbuf .. data
    while s.wait_read and #s.wait_read > 0 do
        local token = s.wait_read[1]
        if not token then
            break
        end
        local n = token[1]
        if n == nil then
            ltask.wakeup(token, s.readbuf)
            s.readbuf = ""
            table.remove(s.wait_read, 1)
        else
            if n > #s.readbuf then
                break
            end
            ltask.wakeup(token, s.readbuf:sub(1, n))
            s.readbuf = s.readbuf:sub(n + 1)
            table.remove(s.wait_read, 1)
        end
    end
    if not s.closed then
        stream_submit_read(s)
    end
end

local function stream_submit_write(s)
    local token = s.wait_write[1]
    if not token then return end
    local data = token[1]
    local reqid = alloc_reqid()
    pending[reqid] = { type = "write", s = s }
    asfd:submit_write(s.fd, data, reqid)
end

local function stream_on_write(s, bytes)
    if not s.wait_write or #s.wait_write == 0 then return end
    local token = s.wait_write[1]
    local data = token[1]
    if bytes < #data then
        -- 部分写：更新剩余数据，重新提交
        token[1] = data:sub(bytes + 1)
        stream_submit_write(s)
    else
        -- 全部写完：唤醒等待者
        table.remove(s.wait_write, 1)
        ltask.wakeup(token, #data)
        if #s.wait_write == 0 and s.wait_close then
            close_stream(s)
        elseif #s.wait_write > 0 then
            -- 队列还有待发数据，继续提交
            stream_submit_write(s)
        end
    end
end

local function create_stream(newfd)
    local s = {
        fd = newfd,
        readbuf = "",
        wait_read = {},
        wait_write = {},
        closed = false,
        read_in_flight = 0,
    }
    status[newfd] = s
    stream_submit_read(s)
    return create_handle(newfd)
end

local S = {}

function S.listen(protocol, ...)
    local fd, err = socket.create(protocol)
    if not fd then
        return nil, err
    end
    local ok, err = fd:bind(...)
    if not ok then
        return nil, err
    end
    ok, err = fd:listen()
    if not ok then
        return nil, err
    end
    local s = {
        fd = fd,
        closed = false,
        is_listener = true,
    }
    status[fd] = s
    return create_handle(fd)
end

function S.connect(protocol, host, port)
    if host and port then
        local ep = socket.endpoint("hostname", host, port)
        if not ep then
            return nil, string.format("resolve hostname failed: %s:%d", host, port)
        end
        local _, _, family = ep:value()
        if family == "inet6" then
            if protocol == "tcp" then
                protocol = "tcp6"
            elseif protocol == "udp" then
                protocol = "udp6"
            end
        end
    end
    local fd, err = socket.create(protocol)
    if not fd then
        return nil, err
    end
    local reqid = alloc_reqid()
    local token = {}
    pending[reqid] = { type = "connect", token = token }
    local ok, cerr = asfd:submit_connect(fd, host, port, reqid)
    if not ok then
        pending[reqid] = nil
        fd:close()
        return nil, cerr
    end
    local result = ltask.wait(token)
    if not result then
        fd:close()
        return nil, "connect failed"
    end
    return create_stream(fd)
end

function S.accept(h)
    local fd = assert(handle[h], "Invalid fd.")
    local s = status[fd]
    assert(s.is_listener, "Not a listener.")
    local reqid = alloc_reqid()
    local token = {}
    pending[reqid] = { type = "accept", token = token }
    asfd:submit_accept(fd, reqid)
    local newfd = ltask.wait(token)
    if not newfd then
        return nil, "accept failed"
    end
    local ok, err = newfd:status()
    if not ok then
        newfd:close()
        return nil, err
    end
    return create_stream(newfd)
end

function S.send(h, data)
    local fd = assert(handle[h], "Invalid fd.")
    local s = status[fd]
    if not s.wait_write then
        error "Write not allowed."
        return
    end
    if s.closed then
        return
    end
    if data == "" then
        return 0
    end
    local token = { data }
    local was_empty = #s.wait_write == 0
    s.wait_write[#s.wait_write + 1] = token
    if was_empty then
        stream_submit_write(s)
    end
    return ltask.wait(token)
end

function S.recv(h, n)
    local fd = assert(handle[h], "Invalid fd.")
    local s = status[fd]
    if not s.readbuf then
        error "Read not allowed."
        return
    end
    -- 已关闭时从缓冲区返回剩余数据
    if s.closed then
        if not n then
            if s.readbuf == "" then
                return
            end
            local ret = s.readbuf
            s.readbuf = ""
            return ret
        else
            if n > #s.readbuf then
                return
            end
            local ret = s.readbuf:sub(1, n)
            s.readbuf = s.readbuf:sub(n + 1)
            return ret
        end
    end
    local sz = #s.readbuf
    if not n then
        if sz == 0 then
            local token = {}
            s.wait_read[#s.wait_read + 1] = token
            stream_submit_read(s)
            return ltask.wait(token)
        end
        local ret = s.readbuf
        s.readbuf = ""
        stream_submit_read(s)
        return ret
    else
        if n <= sz then
            local ret = s.readbuf:sub(1, n)
            s.readbuf = s.readbuf:sub(n + 1)
            stream_submit_read(s)
            return ret
        else
            if n <= kReadBufSize then
                local token = { n }
                s.wait_read[#s.wait_read + 1] = token
                stream_submit_read(s)
                return ltask.wait(token)
            end
            -- 大块读取，分批等待
            local retval = s.readbuf
            s.readbuf = ""
            stream_submit_read(s)
            for _ = 1, (n - sz) // kReadBufSize do
                local token = { kReadBufSize }
                s.wait_read[#s.wait_read + 1] = token
                local r = ltask.wait(token)
                if not r then
                    return
                end
                retval = retval .. r
            end
            local rem = (n - sz) % kReadBufSize
            if rem > 0 then
                local token = { rem }
                s.wait_read[#s.wait_read + 1] = token
                local r = ltask.wait(token)
                if not r then
                    return
                end
                retval = retval .. r
            end
            return retval
        end
    end
end

function S.close(h)
    local fd = handle[h]
    if fd then
        local s = status[fd]
        if not s.closed then
            if s.wait_write and #s.wait_write > 0 then
                -- 有未完成的写操作，等写完再关
                local token = {}
                if s.wait_close then
                    s.wait_close[#s.wait_close + 1] = token
                else
                    s.wait_close = { token }
                end
                ltask.wait(token)
            else
                close_stream(s)
            end
        end
        handle[h] = nil
        handle[fd] = nil
        status[fd] = nil
    end
end

function S.is_closed(h)
    local fd = handle[h]
    if fd then
        return status[fd].closed
    end
    return true
end

local fd_mt = {}
fd_mt.__index = fd_mt

function fd_mt:accept(...)
    local fd, err = ltask.call("accept", self.fd, ...)
    if not fd then
        return nil, err
    end
    return setmetatable({ fd = fd }, fd_mt)
end

function fd_mt:send(...)
    return ltask.call("send", self.fd, ...)
end

function fd_mt:recv(...)
    return ltask.call("recv", self.fd, ...)
end

function fd_mt:close(...)
    return ltask.call("close", self.fd, ...)
end

function fd_mt:is_closed(...)
    return ltask.call("is_closed", self.fd, ...)
end

local net = {}

local function process_completions(iter)
    for reqid, st, data, errcode in iter do
        local p = pending[reqid]
        if not p then
            goto continue
        end
        pending[reqid] = nil
        if p.type == "read" then
            local s = p.s
            if st == SUCCESS then
                stream_on_read(s, data)
            else
                stream_on_read(s, nil)
            end
        elseif p.type == "write" then
            local s = p.s
            if st == SUCCESS then
                stream_on_write(s, data)
            else
                if s.wait_write and #s.wait_write > 0 then
                    local token = table.remove(s.wait_write, 1)
                    ltask.interrupt(token, "Write error.")
                end
                close_stream(s)
            end
        elseif p.type == "accept" then
            ltask.wakeup(p.token, st == SUCCESS and data or nil)
        elseif p.type == "connect" then
            ltask.wakeup(p.token, st == SUCCESS and true or nil)
        end
        ::continue::
    end
end

function net.wait(timeout)
    -- 阻塞等待第一批 completion
    process_completions(asfd:wait(timeout))
    -- 然后在调度器和 poll 之间紧密循环，直到两者都空
    while true do
        local busy = ltask.schedule()
        process_completions(asfd:poll())
        if not busy then
            break
        end
    end
end

function net.listen(...)
    local fd, err = ltask.call("listen", ...)
    if not fd then
        return nil, err
    end
    return setmetatable({ fd = fd }, fd_mt)
end

function net.connect(...)
    local fd, err = ltask.call("connect", ...)
    if not fd then
        return nil, err
    end
    return setmetatable({ fd = fd }, fd_mt)
end

net.fork = ltask.fork
net.schedule = ltask.schedule
net.yield = ltask.yield

ltask.dispatch(S)

return net
