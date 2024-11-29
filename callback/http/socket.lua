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
    local rbuf = ""
    function fd:on_data(data)
        rbuf = rbuf .. data
    end

    local function read(sz)
        if sz == nil then
            net.update(0)
            local r = rbuf
            rbuf = ""
            return r
        else
            while true do
                if #rbuf >= sz then
                    local r = rbuf:sub(1, sz)
                    rbuf = rbuf:sub(sz + 1)
                    return r
                end
                if fd:is_closed() then
                    return ""
                end
                net.update()
            end
        end
    end
    local function write(data)
        fd:write(data)
    end
    local function readall()
        while not fd:is_closed() do
            net.update()
        end
        local r = rbuf
        rbuf = ""
        return r
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
