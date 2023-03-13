import socket
import struct
import time
import urllib.parse

from utils import make_ip_header, make_tcp_header

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
        self.sending_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        self.receiving_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )

    def determine_url_host(self, url):
        """
        Helper function to determine the URL of the
        """
        splitted_url = urllib.parse.urlsplit(url)
        actual_host = splitted_url.netloc
        return actual_host

    # Define function to send TCP segment
    def send_tcp_segment(self, segment, dest_ip, dest_port):
        self.sending_socket.sendto(segment, (dest_ip, dest_port))

    # Define function to receive TCP segment
    def receive_tcp_segment(self):
        segment, _ = self.receiving_socket.recvfrom(BUFFER_LENGTH)
        ip_header_length = (segment[0] & 0xF) * 4
        tcp_header_length = ((segment[ip_header_length + 12] >> 4) & 0xF) * 4
        return segment[ip_header_length : ip_header_length + tcp_header_length]

    def send_ack(self, source_ip, dest_ip, source_port, tcp_header):
        """
        Send ACK message.

        Args:
            source_ip: source IP address
            dest_ip: destination IP address
            source_port (int): source port
            tcp_header (bytes): tcp headers
        """
        ip_header = make_ip_header(54322, source_ip, dest_ip)
        tcp_sequence_num = tcp_header[3]
        tcp_ack_sequence_num = tcp_header[2] + 1  # must increment ack seq number

        tcp_header = make_tcp_header(
            source_port, tcp_sequence_num, tcp_ack_sequence_num, 0, 0, 0, 0, 1
        )
        tcp_header = make_tcp_header(
            source_port,
            tcp_sequence_num,
            tcp_ack_sequence_num,
            0,
            0,
            0,
            0,
            1,
            tcp_header,
            source_ip,
            dest_ip,
            "",
        )
        self.sending_socket.sendto(ip_header + tcp_header, (dest_ip, 0))

    # TODO refactor into multiple functions
    def receive_synack(self, source_ip, dest_ip, src_port):
        """
        Receive a SYNACK from the server.
        """
        tcp_header = None
        while 1:
            packet = self.receiving_socket.recvfrom(BUFFER_LENGTH)[0]
            ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])
            version = (ip_header[0] >> 4) & 0xF
            ip_header_len = version * 4
            ttl = ip_header[5]
            source_ip_addr = socket.inet_ntoa(ip_header[8])
            dest_ip_addr = socket.inet_ntoa(ip_header[9])
            tcp_header = packet[ip_header_len : ip_header_len + 20]
            tcp_header = struct.unpack("!HHLLBBHHH", tcp_header)

            if (
                source_ip_addr == dest_ip
                and dest_ip_addr == source_ip
                and ttl == 18
                and src_port == tcp_header[1]
                and self.syn_start_time - time.time() < 60
            ):
                self.send_ack(source_ip, dest_ip, src_port, tcp_header)
                break
            else:
                self.send_syn(source_ip, dest_ip, src_port)
                break
        return tcp_header

    def send_syn(self, source_ip, dest_ip, source_port) -> None:
        """
        Create and send syn message.

        Args:
            source_ip: source IP address
            dest_ip: destination IP address
            source_port: source port
        """
        ip_header = make_ip_header(54321, source_ip, dest_ip)
        # Make initial TCP header
        tcp_header = make_tcp_header(source_port, 0, 0, 0, 1, 0, 0, 0)
        # Recreate TCP header with checksum included
        tcp_header = make_tcp_header(
            source_port,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            tcp_header=tcp_header,
            source_ip=source_ip,
            dest_ip=dest_ip,
            data="",
        )

        # Send the packet
        self.sending_socket.sendto(ip_header + tcp_header, (dest_ip, 0))
        # Record the time at which SYN is starting
        self.syn_start_time = time.time()

    def determin_local_host_ip_address(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.connect(('www.ccs.neu.edu', 9))
        ip = sock.getsockname()[0]
        return str(ip)

    def request_for_resource(self, source_ip_address, destination_ip_address, source_port, tcp_header, hostname,
                             path_url):
        pass