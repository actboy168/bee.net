local net = require "net"

local error = error
local tostring = tostring

local sockethelper = {}
local socket_error = setmetatable({} , {
    __tostring = function(self)
        local info = self.err_info
        self.err_info = nil
        return info or "[Socket Error]"
    end,

    __call = function (self, info)
        self.err_info = "[Socket Error] : " .. tostring(info)
        return self
    end
})

sockethelper.socket_error = socket_error

local function preread(fd, str)
    return function (sz)
        if str then
            if sz == #str or sz == nil then
                local ret = str
                str = nil
                return ret
            else
                if sz < #str then
                    local ret = str:sub(1,sz)
                    str = str:sub(sz + 1)
                    return ret
                else
                    sz = sz - #str
                    local ret = fd:recv(sz)
                    if ret then
                        return str .. ret
                    else
                        error(socket_error("read failed"))
                    end
                end
            end
        else
            local ret = fd:recv(sz)
            if ret then
                return ret
            else
                error(socket_error("read failed"))
            end
        end
    end
end

function sockethelper.readfunc(fd, pre)
    if pre then
        return preread(fd, pre)
    end
    return function (sz)
        local ret = fd:recv(sz)
        if ret then
            return ret
        else
            error(socket_error("read failed"))
        end
    end
end

function sockethelper.readall(fd)
    while not fd:is_closed() do
        net.yield()
    end
    return fd:recv() or ""
end

function sockethelper.writefunc(fd)
    return function(content)
        local ok = fd:send(content)
        if not ok then
            error(socket_error("write failed"))
        end
    end
end

function sockethelper.connect(host, port, timeout)
    local fd, err = net.connect("tcp", host, port)
    if not fd then
        error(socket_error("connect failed host = " .. host .. ' port = '.. port .. ' timeout = ' .. tostring(timeout) .. ' err = ' .. tostring(err)))
    end
    return fd
end

function sockethelper.close(fd)
    fd:close()
end

function sockethelper.shutdown(fd)
    fd:close()
end

return sockethelper
