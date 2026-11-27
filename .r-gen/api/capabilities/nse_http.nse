-- Execute the installed upstream HTTP NSE analyses through ShakerScan's pinned,
-- metered transport. No global module monkey-patching and no native HTTP fallback.
local nmap = require "nmap"
local stdnse = require "stdnse"
local json = require "json"
local base64 = require "base64"
local shortport = require "shortport"
local allowed = { ["http-methods"]=true, ["http-security-headers"]=true, ["http-trace"]=true }

description = [[ShakerScan worker bridge for installed HTTP NSE service checks.]]
author = "ShakerScan contributors"
license = "AGPL-3.0-only"
categories = {"discovery"}
portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function response_error()
  return {header={}, rawheader={}, body="", ["status-line"]="Transport unavailable"}
end

local function exchange(name, port, method, path, redirects)
  local endpoint = tonumber(stdnse.get_script_args("shakerscan.port"))
  local token = stdnse.get_script_args("shakerscan.token")
  if not endpoint or not token then error("bridge authority unavailable") end
  local socket = nmap.new_socket("tcp", "inet")
  socket:set_timeout(65000)
  local ok = socket:connect("127.0.0.1", endpoint, "tcp")
  if not ok then socket:close(); return response_error() end
  ok = socket:send(json.generate({token=token, script=name, port=port.number,
                                  method=method, path=path, redirects=redirects}) .. "\n")
  if not ok then socket:close(); return response_error() end
  local data
  ok, data = socket:receive_buf("\n", false)
  socket:close()
  if not ok or #data > 524288 then return response_error() end
  local parsed, result = json.parse(data)
  if not parsed or type(result) ~= "table" then return response_error() end
  if result.status == json.NULL then result.status = nil end
  result.body = base64.dec(result.body_base64 or "")
  result.rawheader = result.rawheader or {}
  result.header = result.header or {}
  return result
end

action = function(host, port)
  local output = stdnse.output_table()
  local selected = stdnse.get_script_args("shakerscan.scripts") or ""
  for name in string.gmatch(selected, "[^|]+") do
    if allowed[name] then
      -- Copy the port metadata: following an HTTPS redirect must not label
      -- the originally requested HTTP port as TLS for another native script.
      local analysis_port = {}
      for key, value in pairs(port) do analysis_port[key] = value end
      analysis_port.version = {}
      for key, value in pairs(port.version or {}) do analysis_port.version[key] = value end
      local uses_tls
      local function request(method, path, redirects)
        local result = exchange(name, analysis_port, method, path, redirects)
        if result.status then uses_tls = result.ssl == true end
        return result
      end
      local http = {}
      http.generic_request = function(h, p, method, path, options) return request(method, path, false) end
      http.head = function(h, p, path, options) return request("HEAD", path, true) end
      http.get = function(h, p, path, options) return request("GET", path, true) end
      local service = setmetatable({ssl=function(h, p)
        if uses_tls ~= nil then return uses_tls end
        return shortport.ssl(h, p)
      end}, {__index=shortport})
      local env = setmetatable({SCRIPT_NAME=name, SCRIPT_TYPE="portrule",
        require=function(module)
          if module == "http" then return http end
          if module == "shortport" then return service end
          return require(module)
        end}, {__index=_G})
      local success, structured, rendered = pcall(function()
        local path = nmap.fetchfile("scripts/" .. name .. ".nse")
        if not path then error("installed NSE analysis unavailable") end
        local chunk = assert(loadfile(path, "t", env))
        chunk()
        return env.action(host, analysis_port)
      end)
      if not success then
        output[name] = {output="ERROR: Script execution failed"}
      elseif structured ~= nil or rendered ~= nil then
        if rendered == nil and type(structured) == "table" then
          output[name] = structured
        else
          output[name] = {output=rendered or structured or ""}
        end
      end
    end
  end
  return output
end
