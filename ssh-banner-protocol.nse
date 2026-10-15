local shortport = require "shortport"
local comm = require "comm"

description = [[
Detects the SSH protocol version from an SSH server banner.
]]

author = "Manasvi Dinesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(22, "ssh")

action = function(host, port)
  local status, response = comm.exchange(
    host, port, "SSH-2.0-NmapDA1\r\n",
    {timeout = 5000}
  )

  if not status or type(response) ~= "string" then
    return "No SSH banner received."
  end

  local version = response:match("SSH%-(%d+%.%d+)%-")

  if version then
    return "SSH Protocol Version: " .. version
  else
    return "Unable to identify SSH protocol version."
  end
end
