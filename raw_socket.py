import socket
import struct
import time

# Define constants
IP_VERSION = 4
IP_HEADER_LENGTH = 5
IP_HEADER_SIZE = IP_HEADER_LENGTH * 4
IP_TTL = 255
TCP_PROTOCOL = 6
TCP_WINDOW_SIZE = 1024
TCP_TIMEOUT = 1
WINDOW_SIZE = 4

# Create a raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP_PROTOCOL)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Define function to create TCP segment
def create_tcp_segment(source_port, destination_port, seq_num, ack_num, syn_flag, ack_flag, window_size):
    tcp_header = struct.pack('!HHLLBBHHH', source_port, destination_port, seq_num, ack_num, IP_HEADER_LENGTH << 4, (syn_flag << 1) | ack_flag, TCP_WINDOW_SIZE, 0, window_size)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'), 0, TCP_PROTOCOL, len(tcp_header))
    checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack('!HHLLBBH', source_port, destination_port, seq_num, ack_num, IP_HEADER_LENGTH << 4, (syn_flag << 1) | ack_flag, TCP_WINDOW_SIZE) + struct.pack('H', checksum) + struct.pack('!H', window_size)
    return tcp_header

# Define function to calculate TCP checksum
def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i+1]
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

# Define function to send TCP segment
def send_tcp_segment(segment, dest_ip, dest_port):
    s.sendto(segment, (dest_ip, dest_port))

# Define function to receive TCP segment
def receive_tcp_segment():
    segment, _ = s.recvfrom(65565)
    ip_header_length = (segment[0] & 0xF) * 4
    tcp_header_length = ((segment[ip_header_length+12] >> 4) & 0xF) * 4
    return segment[ip_header_length:ip_header_length+tcp_header_length]

# Define function to send SYN packet and receive SYN-ACK packet
def send_syn_packet(dest_ip, dest_port):
    source_port = 12345 # choose a random port number
    seq_num = 0
    ack_num = 0
    syn_flag = 1
    ack_flag = 0
    window_size = WINDOW_SIZE
    tcp_segment = create_tcp_segment(source_port, dest_port, seq_num, ack_num, syn_flag, ack_flag, window_size)
    send_tcp_segment(tcp_segment, dest_ip, dest_port)
    time.sleep(TCP_TIMEOUT)
    tcp_segment = receive_tcp_segment()
    flags = tcp_segment[13]
    if (flags & 0x12) == 0x12:
        seq_num = struct.unpack('!L', tcp_segment[4:8])[0]
        ack_num = struct.unpack('!L', tcp_segment[8:12])[0]

