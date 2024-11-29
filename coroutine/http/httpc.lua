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
        if protocol ~= "http://" then
            error(string.format("Invalid protocol: %s", protocol))
        end
    end
    local hostaddr, port = host:match "([^:]+):?(%d*)$"
    if port == "" then
        port = 80
    else
        port = tonumber(port)
    end
    return host, hostaddr, port
end

local function connect(hostname)
    local host, hostaddr, port = check_protocol(hostname)
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
    }, host
end

function httpc.request(method, hostname, url, recvheader, header, content)
    local interface, host = connect(hostname)
    local ok, statuscode, body, header = pcall(internal.request, interface, method, host, url, recvheader, header,
        content)
    if ok then
        ok, body = pcall(internal.response, interface, statuscode, body, header)
    end
    interface.close()
    if ok then
        return statuscode, body
    else
        error(body or statuscode)
    end
end

function httpc.head(hostname, url, recvheader, header, content)
    local interface, host = connect(hostname)
    local ok, statuscode = pcall(internal.request, interface, "HEAD", host, url, recvheader, header, content)
    interface.close()
    if ok then
        return statuscode
    else
        error(statuscode)
    end
end

function httpc.request_stream(method, hostname, url, recvheader, header, content)
    local interface, host = connect(hostname)
    local ok, statuscode, body, header = pcall(internal.request, interface, method, host, url, recvheader, header,
        content)
    if not ok then
        interface.close()
        error(statuscode)
    end
    local stream = internal.response_stream(interface, statuscode, body, header)
    stream._onclose = interface.close
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