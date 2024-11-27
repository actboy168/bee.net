local net = require "net"
local internal = require "http.internal"

local string = string
local table = table
local pcall = pcall
local error = error
local pairs = pairs

local httpc = {}

local function check_protocol(host)
    local protocol = host:match("^[Hh][Tt][Tt][Pp][Ss]?://")
    if protocol then
        host = string.gsub(host, "^" .. protocol, "")
        protocol = string.lower(protocol)
        if protocol == "https://" then
            return "https", host
        elseif protocol == "http://" then
            return "http", host
        else
            error(string.format("Invalid protocol: %s", protocol))
        end
    else
        return "http", host
    end
end

local function gen_interface(protocol, fd)
    if protocol ~= "http" then
        error(string.format("Invalid protocol: %s", protocol))
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
            if #rbuf >= sz then
                local r = rbuf:sub(1, sz)
                rbuf = rbuf:sub(sz + 1)
                return r
            end
            repeat
                if #rbuf >= sz then
                    local r = rbuf:sub(1, sz)
                    rbuf = rbuf:sub(sz + 1)
                    return r
                end
                net.update()
            until fd:is_closed()
            return ""
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
    return {
        init = nil,
        close = nil,
        read = read,
        write = write,
        readall = readall,
    }
end

local function connect(host)
    local protocol
    protocol, host = check_protocol(host)
    local hostaddr, port = host:match "([^:]+):?(%d*)$"
    if port == "" then
        port = protocol == "http" and 80 or protocol == "https" and 443
    else
        port = tonumber(port)
    end
    local fd = net.connect("tcp", hostaddr, port)
    if not fd then
        error(string.format("%s connect error host:%s, port:%s", protocol, hostaddr, port))
    end
    local interface = gen_interface(protocol, fd)
    if interface.init then
        interface.init(host)
    end
    return fd, interface, host
end

local function close_interface(interface, fd)
    interface.finish = true
    fd:close()
    if interface.close then
        interface.close()
        interface.close = nil
    end
end

function httpc.request(method, hostname, url, recvheader, header, content)
    local fd, interface, host = connect(hostname)
    local ok, statuscode, body, header = pcall(internal.request, interface, method, host, url, recvheader, header,
        content)
    if ok then
        ok, body = pcall(internal.response, interface, statuscode, body, header)
    end
    close_interface(interface, fd)
    if ok then
        return statuscode, body
    else
        error(body or statuscode)
    end
end

function httpc.head(hostname, url, recvheader, header, content)
    local fd, interface, host = connect(hostname)
    local ok, statuscode = pcall(internal.request, interface, "HEAD", host, url, recvheader, header, content)
    close_interface(interface, fd)
    if ok then
        return statuscode
    else
        error(statuscode)
    end
end

function httpc.request_stream(method, hostname, url, recvheader, header, content)
    local fd, interface, host = connect(hostname)
    local ok, statuscode, body, header = pcall(internal.request, interface, method, host, url, recvheader, header,
        content)
    interface.finish = true -- don't shutdown fd in timeout
    local function close_fd()
        close_interface(interface, fd)
    end
    if not ok then
        close_fd()
        error(statuscode)
    end
    -- todo: stream support timeout
    local stream = internal.response_stream(interface, statuscode, body, header)
    stream._onclose = close_fd
    return stream
end

function httpc.get(...)
    return httpc.request("GET", ...)
end

local function escape(s)
    return (string.gsub(s, "([^A-Za-z0-9_])", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

function httpc.post(host, url, form, recvheader)
    local header = {
        ["content-type"] = "application/x-www-form-urlencoded"
    }
    local body = {}
    for k, v in pairs(form) do
        table.insert(body, string.format("%s=%s", escape(k), escape(v)))
    end

    return httpc.request("POST", host, url, recvheader, header, table.concat(body, "&"))
end

return httpc
