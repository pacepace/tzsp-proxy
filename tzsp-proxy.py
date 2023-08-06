#!/usr/bin/env python3
# Author: Matthew Ciantar
#
# Listens for TZSP on port 37008, extract the encapsulated packet
# and send it to the local interface
#
# Version 1.1
# 2021-04-02
#
# modified to make it work more easily with docker
# 2023-08-05
#

# tzsp packets received on interface defined by IFACE_TZSP environment variable.
# promiscious interface is defined by IFACE_SNIFFER environment variable.

import _thread
import fcntl
import socket
import struct
import os

from collections import Counter
from dotenv import load_dotenv
from scapy.all import *

# load enviroment from .env
load_dotenv()

# packet count
packetCount = Counter(count=0)

# classes

# return the mac address of the interface
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])

# extract each packet received and resend it to the local interface
# the original destination mac will be lost
def processPacketCapture ( tzspCapture ):
    try:
        packetCount.update()
        tzspRawPacket = tzspCapture[0]
        tzspPacket = TZSP(tzspRawPacket[UDP].load)
        rawPacket = tzspPacket[2]
        try:
            rawPacket[Ether].dst = mac_str
            sendp(rawPacket, iface=IFACE_SNIFFER, verbose=False)
            if (SNIFFER_SEND_VERBOSE) or (packetCount['count'] % PACKET_COUNT_LOG == 0):
                if IP in rawPacket:
                    print(f'Source IP: {rawPacket[IP].src:<15} Destination IP: {rawPacket[IP].dst:<15}')
                if IPv6 in rawPacket:
                    print(f'Source IPv6: {rawPacket[IPv6].src:<30} Destination IPv6: {rawPacket[IPv6].dst:<30}')
        except Exception as err:
            print(f'Send Exception: {err}')
            #print("Exception!")
            #print(repr(tzspRawPacket))
            pass
    except Exception as err:
        print(f'Capture Exception: {err}')
        pass

# convert whacko strings to boolean (looking at you polycom)
def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).
    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    else:
        return False

print('... tzsp proxy starting ...')
# tzsp receive interface
IFACE_TZSP = os.environ.get('IFACE_TZSP', default='eth0')
# tzsp receive port
IFACE_TZSP_PORT = int(os.environ.get('IFACE_TZSP_PORT', default=37008))
# output raw packets to this sniffer interface
IFACE_SNIFFER = os.environ.get('IFACE_SNIFFER', default='eth0')
# log every N packets
PACKET_COUNT_LOG = int(os.environ.get('PACKET_COUNT_LOG', default=10000))
# verbose raw packet sending
SNIFFER_SEND_VERBOSE = os.environ.get('SNIFFER_SEND_VERBOSE', default=False)
SNIFFER_SEND_VERBOSE = strtobool(SNIFFER_SEND_VERBOSE)

# log settings
print (f'... IFACE_TZSP: {IFACE_TZSP} ...')
print (f'... IFACE_SNIFFER: {IFACE_SNIFFER} ...')
print (f'... SNIFFER_SEND_VERBOSE: {SNIFFER_SEND_VERBOSE} ...')
print (f'... PACKET_COUNT_LOG: {PACKET_COUNT_LOG} ...')

# load tzsp library
print('... tzsp library loading ...')
load_contrib('tzsp')

# get the mac address of the sniffer interface
mac_str = str(getHwAddr(IFACE_SNIFFER))

print('... tzsp capturing ...')
# TODO: add signal handling
while True:
    sniff(prn=processPacketCapture, count=1000, iface=IFACE_TZSP, filter = 'udp port 37008', store=0)
    newPacketCount = Counter(count=1000)
    packetCount.update(newPacketCount)
    if packetCount['count'] % PACKET_COUNT_LOG == 0:
        print(f'... {packetCount} captured ...')
print('... tzsp proxy stopping ...')
