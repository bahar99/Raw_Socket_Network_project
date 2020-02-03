import socket
import socket,sys,struct,os
from netaddr import IPNetwork,IPAddress
from ctypes import *
from struct import *

srcip   = "127.0.0.1"
destip  = "127.0.0.1"
srcport = 9003
dstport = 8003

"""
Create new socket
returns tuple (True,socket) if successful or (False,error message) otherwise.
"""
def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #With the setsockopt() we tell the kernel not to generate an IP header, since we are providing it ourselves.
        s.bind((srcip,srcport))
    except Exception as e:
        print('Socket could not be created.  Message: ' + str(e))
        return (False,'Socket could not be created.  Message: ' + str(e))

    return (True,s)

"""
we must define the functions with which we will create and parse the packages.
"""

def checksum(msg):
    s = 0


    # loop taking 2 characters at a time
    for i in range(0, len(msg)-1, 2):
        w = msg[i] + ((msg[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff)
    s = s + (s >> 16)

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

"""
Construct an IP header.
For a TCP packet, only source and destination IPs need to be set.
source_ip = str IP of sender
dest_ip   = str IP of receiver
ihl       = Internet Header Length. Default is 5 (20 bytes).
ver       = IP version. default is 4
pid       = ID of the packet. So that split packets may be reassembled in order.
offs      = Fragment offset if any. default 0
ttl       = Time To Live for the packet. default 255
proto     = Protocol for contained packet. default is TCP.
"""

def construct_ip_header(source_ip,dest_ip,ihl=5,ver=4,pid=0,offs=0,ttl=255,proto=socket.IPPROTO_TCP):
    ip_ihl = ihl
    ip_ver = ver
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = pid   #Id of this packet
    ip_frag_off = offs
    ip_ttl = ttl
    ip_proto = proto
    ip_check = 0   # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header

"""
Construct a TCP header.
source_ip = str IP of sender
dest_ip   = str IP of receiver
srcp      = source port number
dstp      = receiver port number
seq       = TCP sequence number: set a random number for first package and the ack number of previous received ACK package otherwise.
ackno     = TCP ack number: previous received seq + number of bytes received
flags     = TCP flags in an array with the structure [HS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
user_data = string with the data to send
doff      = data offset, default 0
wsize     = max window size for sender
urgptr    = Urgent pointer if URG flag is set
"""
def construct_tcp_header(source_ip,dest_ip,srcp,dstp,seq,ackno,flags,user_data="",doff=5,wsize=5840,urgptr=0):

    tcp_source = srcp   # source port

    tcp_dest = dstp   # destination port

    tcp_seq = seq
    tcp_ack_seq = ackno
    tcp_doff = doff


    #tcp flags
    #flags=[HS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
    tcp_fin = flags[8]

    tcp_syn = flags[7]
    tcp_rst = flags[6]
    tcp_psh = flags[5]
    tcp_ack = flags[4]
    tcp_urg = flags[3]
    tcp_window = socket.htons(5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = urgptr

    tcp_offset_res = (tcp_doff << 4) + 0

    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)

    psh = psh + tcp_header + user_data.encode('utf-8')


    tcp_check = checksum(psh)


    # make the tcp header again and fill the correct checksum
    tcp_header = struct.pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + struct.pack('H' , tcp_check) + struct.pack('!H' , tcp_urg_ptr)
    return tcp_header

def construct_tcp_packet(ip_header,tcp_header,user_data=""):
    packet=''
    packet = ip_header + tcp_header + user_data.encode('utf-8')
    return packet



# class IP(Structure):
#
#     _fields_ = [
#         ("ihl",           c_ubyte,4),
#         ("version",       c_ubyte,4),
#         ("tos",           c_ubyte),
#         ("len",           c_ushort),
#         ("id",            c_ushort),
#         ("offset",        c_ushort),
#         ("ttl",           c_ubyte),
#         ("protocol_num",  c_ubyte),
#         ("sum",           c_ushort),
#         ("src",           c_uint),
#         ("dst",           c_uint)
#     ]
#
#     def __new__(self, socket_buffer=None):
#             return self.from_buffer_copy(socket_buffer)
#
#     def __init__(self, socket_buffer=None):
#
#         # map protocol constants to their names
#         self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
#
#         # human readable IP addresses
#         self.src_address = socket.inet_ntoa(struct.pack("">1)&1)
#         self.rst = (flagsi>>2)&1
#         self.psh = (flagsi>>3)&1
#         self.ack = (flagsi>>4)&1
#         self.urg = (flagsi>>5)&1
#         self.ece = (flagsi>>6)&1
#         self.cwr = (flagsi>>7)&1
#         self.hs  = (flagsi>>8)&1
#
#         self.seq_no = socket.htonl(self.seqno)
#         self.ack_no = socket.htonl(self.ackno)
#         self.win_size = socket.htons(self.wsize)



"""
TCP 3 way handshake on socket s
returns tuple (True,"") if successful or (False,error message) otherwise.
"""
def three_way_handshake(s,destip):
    try:
        global latest_raw_buffer
        global latest_tcp_header
        #send SYN
        iphead=construct_ip_header(srcip,destip)

        tcphead=construct_tcp_header(srcip,destip,srcport,dstport,1,0,[0,0,0,0,0,0,0,1,0])

        tcppacket =construct_tcp_packet(iphead,tcphead)

        ret = s.sendto(tcppacket,(destip, dstport))
        #receive ACK/SYN
        raw_buffer = s.recv(4096)

        latest_raw_buffer = raw_buffer
        tcp_header= raw_buffer[20:40];

        tcph = unpack('!HHLLHHHH', tcp_header)
        #tcp_header =TCP(raw_buffer[20:40])

        latest_tcp_header = raw_buffer[20:40]

        #send ack package
        iphead=construct_ip_header(srcip,destip)
        tcphead=construct_tcp_header(srcip,destip,srcport,dstport,2,int(tcph[2]) + 1,[0,0,0,0,1,0,0,0,0])
        
        tcppacket = construct_tcp_packet(iphead,tcphead)
        ret = s.sendto(tcppacket,(destip, dstport))


    except Exception as e:
        print('Three way handshake failed: '  + str(e))
        return (False,'Three way handshake failed: '  + str(e))

    return (True,s)
s=create_socket()

if s[0]:
    three_way_handshake(s[1],destip)
