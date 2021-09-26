#!/usr/bin/python
#
# Copyright 2020 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binascii
import fcntl
import os
import select
import struct
import sys
import time
from socket import *
from scapy import all as scapy


ICMPV6_FILTER = 1
IFNAMSIZ = 16
SO_BINDTODEVICE = 25

IPV6_HDRINCL = 36

# 64:ff9b::/96, 1800s
OPTION = binascii.unhexlify(b"260207080064ff9b0000000000000000")
INTERVAL = 240

LOG = True


class RaDaemon(object):


  def __init__(self, iface):
    self.iface = iface


  def Log(self, msg):
    if LOG:
      sys.stderr.write(msg + "\n")
      sys.stdout.flush()


  @staticmethod
  def GetInterfaceIndex(ifname):
    s = socket(AF_INET6, SOCK_DGRAM, 0)
    ifname = bytes(ifname.encode("ascii"))  # For python 2 and 3 compatibility.
    ifr = struct.pack("%dsi" % IFNAMSIZ, ifname, 0)
    ifr = fcntl.ioctl(s, scapy.SIOCGIFINDEX, ifr)
    return struct.unpack("%dsi" % IFNAMSIZ, ifr)[1]


  def SendRa(self, s, dst=None):
    if dst is not None:
      msg = "Unicasting response to %s" % str(dst)
    else:
      dst = "ff02::1%" + self.iface
      msg = "Multicasting RA to %s" % (dst)

    self.Log(msg)

    dstaddr = getaddrinfo(dst, 0, AF_INET6, 0, 0, AI_NUMERICHOST)[0]
    sockaddr = dstaddr[4]

    dst = dst.split("%")[0]
    pkt = (scapy.IPv6(src="fe80::6464", dst=dst) /
           scapy.ICMPv6ND_RA(prf=3, routerlifetime=0) /
           OPTION)

    # Passing an interface to scapy.send() doesn't seem to work?
    # scapy.send(pkt, iface=self.iface)

    s.sendto(bytes(pkt), sockaddr)


  def MaybeRespondToRs(self, s):
    try:
      data, src = s.recvfrom(4096)
    except IOError:
      self.Log("Read error:", e)
      return

    # Was the RS received on the correct interface?
    scopeid = src[3]
    if not scopeid:
      self.Log("Ignoring source address with no scope ID")
      return
    if scopeid != self.GetInterfaceIndex(self.iface):
      return

    src = src[0]  # Don't need the scope ID because LL addresses are scoped.
    self.Log("Packet from %s: %s" % (src, binascii.hexlify(data)))

    try:
      self.SendRa(s, src)
    except IOError as e:
      self.Log("Error sending RA: %s" % e)


  def OpenSocket(self):
    s = socket(AF_INET6, SOCK_RAW | os.O_NONBLOCK, IPPROTO_ICMPV6)
    s.setsockopt(IPPROTO_IPV6, IPV6_HDRINCL, 1)
    s.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255)
    s.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255)

    # Don't bind to a specific index because otherwise we'd have to reopen
    # the socket when the interface goes away or changes ifindex.
    ifindex = 0
    addr = inet_pton(AF_INET6, "ff02::2")
    mreq = struct.pack("=16si", addr, ifindex)
    s.setsockopt(IPPROTO_IPV6, IPV6_JOIN_GROUP, mreq)

    rs = 133
    icmpv6_filter = bytearray(32 * [255])
    icmpv6_filter[rs >> 3] &= ~(1 << ((rs & 7)))
    icmpv6_filter = bytes(icmpv6_filter)
    s.setsockopt(IPPROTO_ICMPV6, ICMPV6_FILTER, icmpv6_filter)

    s.bind(("::", 0))

    return s


  def PollLoop(self, s):
    p = select.poll()
    p.register(s, select.POLLIN)
    now = int(time.time() * 1000)
    next = now + INTERVAL * 1000

    self.SendRa(s, None)
    while True:
      timeout = max(0, next - now)
      events = p.poll(timeout)
      now = time.time() * 1000
      if events:
        self.MaybeRespondToRs(s)
      else:
        self.SendRa(s, None)
        next = now + INTERVAL * 1000


  def Start(self):
    s = self.OpenSocket()
    self.PollLoop(s)


def main(args):
  if len(args) != 2:
    sys.stderr.write("Usage: %s <interface>\n" % args[0])
    sys.exit()

  iface = args[1]
  r = RaDaemon(iface)
  r.Start()


if __name__ == "__main__":
  main(sys.argv)
