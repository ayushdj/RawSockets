import socket
import struct
import time
import urllib.parse

from utils import calculate_checksum, make_tcp_header, write_file

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
