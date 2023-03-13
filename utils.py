# Utility functions to aid with networking operations.

import socket
import struct
import sys
import urllib.parse

CLRF = "\r\n\r\n"
IP_HEADER_LENGTH = 5
IP_LENGTH_OFFSET = 20
IP_VERSION = 4
TCP_PROTOCOL = socket.IPPROTO_TCP
MAX_WINDOW_SIZE = 1000


def calculate_checksum(message):
    """
    Calculate the checksum of the given message.

    Args:
        message: characters to calculate checksum for.
    Returns:
        checksum: integer checksum value
    """
    # If the length of the message is odd, pad with a zero byte
    if len(message) % 2 != 0:
        message += b"\0"
    # Calculate the one's complement sum of the message contents
    s = sum(struct.unpack("!{}H".format(len(message) // 2), message))
    # Fold the 32-bit sum into 16 bits by adding the carry bits
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    # Take the one's complement of the result
    checksum = (~s) & 0xFFFF
    return checksum


def write_file(file, response_dict: dict):
    """
    Write the response from a dictionary to a file.

    Args:
        file: file pointer
        response_dict(dict): dictionary mapping int to strings as parts of response.
    """
    response = "".join([response_dict[key] for key in sorted(response_dict)])
    # Make sure valid HTTP Response Code
    if response.find("200 OK") < 0:
        print("[ERROR]: Invalid HTTP Response Code")
        sys.exit()
    # Write the response to the file if valid response code.
    with open(file, "w") as write_file:
        ordered_seq = sorted(response_dict.keys())
        for idx, element in enumerate(ordered_seq):
            if idx == 0:
                write_file.writelines(response_dict[element].split(CLRF)[1])
            write_file.writelines(response_dict[element])


def make_tcp_header(
        source_port,
        sequence_number,
        ack_number,
        finish_flag,
        syn_flag,
        reset_flag,
        push_flag,
        ack_flag,
        tcp_header=None,
        source_ip=None,
        dest_ip=None,
        data=None,
) -> bytes:
    """
    Generate a TCP Header and optionally include a checksum if an existing header is passed in.
    Reference: https://www.site24x7.com/learn/linux/tcp-flags.html

    Args:
        source_port (int): TCP port from source
        sequence_number (int): number in sequence network order
        ack_number (int): number in sequence for acknowledgement
        finish_flag (int): terminates TCP connection
        syn_flag (int): create TCP connection (handshake)
        reset_flag (int): terminate the connection andn drop data in transit
        push_flag (int): bypass network buffering
        ack_flag (int): acknowledge data reception or synchronization packets
        tcp_header (bytes): packed TCP header to add checksum to (optional)
        source_ip (int): IP of source (optional)
        dest_ip (int): IP of destination (optional)
        data: data to get length of to include in header (optional)
    """
    # Create the base tcp header
    tcp_dest_port = 80
    tcp_doff = 5 << 4
    tcp_urg_ptr = 0
    tcp_flags = (
            finish_flag
            + (syn_flag << 1)
            + (reset_flag << 2)
            + (push_flag << 3)
            + (ack_flag << 4)
            + (tcp_urg_ptr << 5)
    )

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        tcp_dest_port,
        sequence_number,
        ack_number,
        tcp_doff,
        tcp_flags,
        socket.htons(MAX_WINDOW_SIZE),  # window size
        0,  # checksum is 0 to begin
        tcp_urg_ptr,
    )

    # Optionally include a checksum to the tcp header if optional fields passed in.
    if tcp_header and source_ip and dest_ip and data:
        source_address = socket.inet_aton(source_ip)
        destination_address = socket.inet_aton(dest_ip)
        header_size = len(tcp_header) + len(data)

        # Construct the packet with corresponding fields
        packet = (
                struct.pack(
                    "!4s4sBBH",
                    source_address,
                    destination_address,
                    0,
                    TCP_PROTOCOL,
                    header_size,
                )
                + tcp_header
                + data
        )

        tcp_header = (
                struct.pack(
                    "!HHLLBBHHH",
                    source_port,
                    tcp_dest_port,
                    sequence_number,
                    ack_number,
                    tcp_doff,
                    tcp_flags,
                    socket.htons(MAX_WINDOW_SIZE),  # window size
                )
                + struct.pack("H", calculate_checksum(packet))
                + struct.pack("!H", tcp_urg_ptr)
        )

    return tcp_header


def make_ip_header(src_ip, dest_ip, protocol, data="") -> bytes:
    """
    Generate IP header.

    Args:
        src_ip: source IP address
        dest_ip: destination IP address
        protocol: network protocol to use
        data: used for adding len of data to header
    Returns
        IP header packed
    """
    # IPv4 header fields
    version = IP_VERSION
    ip_header_length = IP_HEADER_LENGTH
    tos = 0
    total_len = len(data) + IP_LENGTH_OFFSET
    identifier = 54321
    flags = 0
    fragmentation_offset = 0
    ip_ttl = 255
    checksum = 0
    src_ip_packed = socket.inet_aton(src_ip)
    dest_ip_packed = socket.inet_aton(dest_ip)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) + ip_header_length,
        tos,
        total_len,
        identifier,
        (flags << 13) + fragmentation_offset,
        ip_ttl,
        protocol,
        checksum,
        src_ip_packed,
        dest_ip_packed,
    )

    # calculate the checksum using the packed header
    checksum = calculate_checksum(header)
    # replace the placeholder value with the actual checksum
    return header[:10] + struct.pack("!H", checksum) + header[12:]

def determine_destination_ip_address(url):
    returned_tuple = urllib.parse.urlparse(url)
    host_name = returned_tuple.hostname
    destnation_ip_address = socket.gethostbyname(host_name.decode())
    return destnation_ip_address
