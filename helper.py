import socket
import struct
import time
import urllib.parse

# Define constants
TCP_PROTOCOL = socket.IPPROTO_TCP
RAW_PROTOCOL = socket.IPPROTO_RAW

# IP constants
IP_VERSION = 4
IP_HEADER_LENGTH = 5
IP_HEADER_SIZE = IP_HEADER_LENGTH * 4
IP_TTL = 255
IP_LENGTH_OFFSET = 20

# TCP constants
TCP_WINDOW_SIZE = 1024
TCP_TIMEOUT = 1
WINDOW_SIZE = 4
BUFFER_LENGTH = 65565


class MyRawSocket:
    """
        Defines a custom implementation for a raw socket
    """

    def __init__(self):
        # Create 2 sockets - one for sending the raw data, one for receiving TCP data
        self.sending_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, RAW_PROTOCOL)
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP_PROTOCOL)

    def determine_url(self, url):
        """
            Helper function to determine the URL of the
        """
        splitted_url = urllib.parse.urlsplit(url)
        actual_host = splitted_url.netloc
        print(actual_host)

    # Define function to create TCP segment
    def make_tcp_header(self, source_port, destination_port, seq_num, ack_num, syn_flag, ack_flag, window_size):
        """
            This function generates the TCP header
        """
        tcp_header = struct.pack('!HHLLBBHHH', source_port, destination_port, seq_num, ack_num, IP_HEADER_LENGTH << 4,
                                 (syn_flag << 1) | ack_flag, TCP_WINDOW_SIZE, 0, window_size)
        pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'), 0,
                                    TCP_PROTOCOL, len(tcp_header))
        checksum = self.calculate_checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack('!HHLLBBH', source_port, destination_port, seq_num, ack_num, IP_HEADER_LENGTH << 4,
                                 (syn_flag << 1) | ack_flag, TCP_WINDOW_SIZE) + struct.pack('H',
                                                                                            checksum) + struct.pack(
            '!H', window_size)
        return tcp_header

    def make_ip_header(self, src_ip, dest_ip, protocol, data):
        # IPv4 header fields
        version = IP_VERSION
        ip_header_length = IP_HEADER_LENGTH
        tos = 0
        total_len = len(data) + IP_LENGTH_OFFSET
        identifier = 54321
        flags = 0
        fragmentation_offset = 0
        ip_ttl = IP_TTL
        checksum = 0
        src_ip_packed = socket.inet_aton(src_ip)
        dest_ip_packed = socket.inet_aton(dest_ip)

        header = struct.pack('!BBHHHBBH4s4s', (version << 4) + ip_header_length, tos, total_len,
                             identifier, (flags << 13) + fragmentation_offset, ip_ttl, protocol, checksum,
                             src_ip_packed, dest_ip_packed)

        # calculate the checksum using the packed header
        checksum = self.calculate_checksum(header)

        # replace the placeholder value with the actual checksum
        header = header[:10] + struct.pack('!H', checksum) + header[12:]

        return header

    def calculate_checksum(self, data):
        """
            Function defines the TCP checksum -> move to util file
        """
        if len(data) % 2 == 1:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF

    # Define function to send TCP segment
    def send_tcp_segment(self, segment, dest_ip, dest_port):
        self.sending_socket.sendto(segment, (dest_ip, dest_port))


# Define function to receive TCP segment
    def receive_tcp_segment(self):
        segment, _ = self.receiving_socket.recvfrom(BUFFER_LENGTH)
        ip_header_length = (segment[0] & 0xF) * 4
        tcp_header_length = ((segment[ip_header_length + 12] >> 4) & 0xF) * 4
        return segment[ip_header_length:ip_header_length + tcp_header_length]


    def send_syn_packet(self, dest_ip, dest_port):
        """
            todo
        """
        pass

    def send_acknowledgement(self):
        """
            todo
        """

    def receive_acknowledgement(self):
        """
            todo
        """

    def make_syn(self):
        """
            todo
        """