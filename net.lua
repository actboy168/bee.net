local socket = require "bee.socket"

local rds = {}
local wds = {}
local map = {}

local function on_event(self, name, ...)
    local f = self._event[name]
    if f then
        f(self, ...)
    end
end

local function open_read(self)
    local fd = self._fd
    for _, r in ipairs(rds) do
        if r == fd then
            return
        end
    end
    rds[#rds+1] = fd
end

local function open_write(self)
    local fd = self._fd
    for _, w in ipairs(wds) do
        if w == fd then
            return
        end
    end
    wds[#wds+1] = fd
end

local function close_read(self)
    local fd = self._fd
    for i, f in ipairs(rds) do
        if f == fd then
            rds[i] = rds[#rds]
            rds[#rds] = nil
            return
        end
    end
end

local function close_write(self)
    local fd = self._fd
    for i, f in ipairs(wds) do
        if f == fd then
            wds[i] = wds[#wds]
            wds[#wds] = nil
            return
        end
    end
end

local function close(self)
    local fd = self._fd
    on_event(self, "close")
    fd:close()
    map[fd] = nil
end

local stream_mt = {}
local stream = {}
stream_mt.__index = stream
function stream_mt:__newindex(name, func)
    if name:sub(1, 3) == "on_" then
        self._event[name:sub(4)] = func
    end
end
function stream:write(data)
    if self.shutdown_w then
        return
    end
    if data == "" then
        return
    end
    if self._writebuf == "" then
        open_write(self)
    end
    self._writebuf = self._writebuf .. data
end
function stream:is_closed()
    return self.shutdown_w and self.shutdown_r
end
function stream:close()
    self.shutdown_r = true
    close_read(self)
    if self.shutdown_w or self._writebuf == ""  then
        self.shutdown_w = true
        close_write(self)
        close(self)
    end
end
function stream:update(timeout)
    local fd = self._fd
    local r = {fd}
    local w = r
    if self._writebuf == "" then
        w = nil
    end
    local rd, wr = socket.select(r, w, timeout or 0)
    if rd then
        if #rd > 0 then
            self:select_r()
        end
        if #wr > 0 then
            self:select_w()
        end
    end
end
function stream:close_w()
    close_write(self)
    if self.shutdown_r then
        close_read(self)
        close(self)
    end
end
function stream:select_r()
    local data = self._fd:recv()
    if data == nil then
        self:close()
    elseif data == false then
    else
        on_event(self, "data", data)
    end
end
function stream:select_w()
    local n = self._fd:send(self._writebuf)
    if n == nil then
        self.shutdown_w = true
        self:close_w()
    else
        self._writebuf = self._writebuf:sub(n + 1)
        if self._writebuf == "" then
            self:close_w()
        end
    end
end

local function accept_stream(fd)
    local s = {
        _fd = fd,
        _event = {},
        _writebuf = "",
        shutdown_r = false,
        shutdown_w = false,
    }
    map[fd] = s
    open_read(s)
    return setmetatable(s, stream_mt)
end
local function connect_stream(fd)
    local s = map[fd]
    setmetatable(s, stream_mt)
    open_read(s)
    if s._writebuf ~= "" then
        stream.select_w(s)
    else
        close_write(s)
    end
end


local listen_mt = {}
local listen = {}
listen_mt.__index = listen
function listen_mt:__newindex(name, func)
    if name:sub(1, 3) == "on_" then
        self._event[name:sub(4)] = func
    end
end
function listen:is_closed()
    return self.closed
end
function listen:close()
    self.closed = true
    close_read(self)
    close(self)
end
function listen:update(timeout)
    local fd = self._fd
    local r = {fd}
    local rd = socket.select(r, nil, timeout or 0)
    if rd then
        if #rd > 0 then
            self:select_r()
        end
    end
end
function listen:select_r()
    local newfd = self._fd:accept()
    if newfd:status() then
        local news = accept_stream(newfd)
        on_event(self, "accept", news)
    end
end
local function new_listen(fd)
    local s = {
        _fd = fd,
        _event = {},
        closed = false,
    }
    map[fd] = s
    return setmetatable(s, listen_mt)
end

local connect_mt = {}
local connect = {}
connect_mt.__index = connect
function connect_mt:__newindex(name, func)
    if name:sub(1, 3) == "on_" then
        self._event[name:sub(4)] = func
    end
end
function connect:recv()
    return ""
end
function connect:write(data)
    if data == "" then
        return
    end
    self._writebuf = self._writebuf .. data
end
function connect:is_closed()
    return self.shutdown_w
end
function connect:close()
    self.shutdown_w = true
    close_write(self)
    close(self)
end
function connect:update(timeout)
    local fd = self._fd
    local w = {fd}
    local rd, wr = socket.select(nil, w, timeout or 0)
    if rd then
        if #wr > 0 then
            self:select_w()
        end
    end
end
function connect:select_w()
    local ok, err = self._fd:status()
    if ok then
        connect_stream(self._fd)
        on_event(self, "connect")
    else
        on_event(self, "error", err)
        close(self)
    end
end
local function new_connect(fd)
    local s = {
        _fd = fd,
        _event = {},
        _writebuf = "",
        shutdown_r = false,
        shutdown_w = false,
    }
    map[fd] = s
    return setmetatable(s, connect_mt)
end

local m = {}

function m.listen(...)
    local fd, err = socket.bind(...)
    if not fd then
        return fd, err
    end
    rds[#rds+1] = fd
    return new_listen(fd)
end

function m.connect(...)
    local fd, err = socket.connect(...)
    if not fd then
        return fd, err
    end
    wds[#wds+1] = fd
    return new_connect(fd)
end

function m.update(timeout)
    local rd, wr = socket.select(rds, wds, timeout or 0)
    if rd then
        for _, fd in ipairs(rd) do
            local s = map[fd]
            s:select_r()
        end
        for _, fd in ipairs(wr) do
            local s = map[fd]
            s:select_w()
        end
    end
end

return m
