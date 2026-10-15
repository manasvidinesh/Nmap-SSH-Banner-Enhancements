local shortport = require "shortport"
local comm = require "comm"

description = [[
Identifies SSH server software and version from its banner.
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

  local software = response:match("SSH%-%d+%.%d+%-([^%s\r\n]+)")

  if software then
    return "SSH Server Software: " .. software
  else
    return "Software information not available."
  end
end
