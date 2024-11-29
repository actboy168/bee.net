local net = require "net"

return function(host)
    local hostaddr, port = host:match "([^:]+):?(%d*)$"
    if port == "" then
        port = 80
    else
        port = tonumber(port)
    end
    local fd = net.connect("tcp", hostaddr, port)
    if not fd then
        error(string.format("http connect error host:%s, port:%s", hostaddr, port))
    end
    local function read(sz)
        if sz == nil then
            return fd:recv()
        end
        local rbuf = fd:recv(sz)
        if #rbuf == sz then
            return rbuf
        elseif #rbuf > sz then
            error("socket returns unexpected value")
        end
        local strbuilder = { rbuf }
        sz = sz - #rbuf
        while sz > 0 do
            local buf = fd:recv(sz)
            if #buf > sz then
                error("socket returns unexpected value")
            end
            strbuilder[#strbuilder + 1] = buf
            sz = sz - #buf
        end
        return table.concat(strbuilder)
    end
    local function write(data)
        fd:send(data)
    end
    local function readall()
        while not fd:is_closed() do
            net.yield()
        end
        local r = fd:recv()
    end
    local function close()
        fd:close()
    end
    return {
        read = read,
        write = write,
        readall = readall,
        close = close,
    }
end
