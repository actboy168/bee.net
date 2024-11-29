local internal = require "http.internal"
local socket = require "http.socket"

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
    return host
end

function httpc.request(method, hostname, url, recvheader, header, content)
    local host = check_protocol(hostname)
    local interface = socket(host)
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
    local host = check_protocol(hostname)
    local interface = socket(host)
    local ok, statuscode = pcall(internal.request, interface, "HEAD", host, url, recvheader, header, content)
    interface.close()
    if ok then
        return statuscode
    else
        error(statuscode)
    end
end

function httpc.request_stream(method, hostname, url, recvheader, header, content)
    local host = check_protocol(hostname)
    local interface = socket(host)
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
