#!/usr/bin/env python3
# Author: Matthew Ciantar
#
# Listens for TZSP on port 37008, extract the encapsulated packet
# and send it to the local interface
#
# Version 1.1
# 2021-04-02
#
# Modified to make it work more easily with Docker
# 2023-08-05
#

# Script assumes that the TZSP Packets will be received on eth0. Replace on line 48 if that is different for you.
# Script assumes that the promiscious interface is bond0. Replace this  on line 40 with the interface where you sensor is listening. 

import _thread
import fcntl
import socket
import struct
import os

from dotenv import load_dotenv
from scapy.all import *

# load enviroment from .env
load_dotenv()

# tzsp receive interface
IFACE_TZSP = os.environ.get('IFACE_TZSP', default="eth0")
# output suricata interface
IFACE_SNIFFER = os.environ.get('IFACE_SNIFFER', default="eth0")

# load tzsp library
load_contrib("tzsp")

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])

mac_str = str(getHwAddr(IFACE_SNIFFER))

# extract each packet received and resend it to the local interface
# the original destination mac will be lost
def processPacketCapture ( tzspCapture ):
        try:
             tzspRawPacket = tzspCapture[0]
             tzspPacket = TZSP(tzspRawPacket[UDP].load)
             rawPacket = tzspPacket[2]
             try:
                 rawPacket[Ether].dst = mac_str
                 sendp(rawPacket, iface=IFACE_SNIFFER, verbose=False)
             except:
                 print("Exception!")
                 print(repr(tzspRawPacket))
        except:
             print("Exception!")

# start sniffing indefinitely
sniff(prn=processPacketCapture, iface=IFACE_TZSP, filter = "udp port 37008", store=0)
