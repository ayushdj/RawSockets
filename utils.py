# Utility functions to aid with networking operations.

import socket
import struct
import sys

CLRF = "\r\n\r\n"
IP_HEADER_LENGTH = 5
IP_LENGTH_OFFSET = 20
IP_VERSION = 4
TCP_PROTOCOL = socket.IPPROTO_TCP


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


# TODO: fix this function so that it works to add checksum and/or create blank header.
def make_tcp_header(
    source_port,
    destination_port,
    seq_num,
    ack_num,
    syn_flag,
    ack_flag,
    window_size,
    source_ip=None,
    dest_ip=None,
    input_tcp_header=None,
    data=None,
):
    """
    Generate TCP header.

    Args:
        source_port(int): source port
        destination_port(int): destination port
        seq_num(int): number within packet sequence
        ack_num(int): acknowledgement number
        syn_flag(int): flag denoting synchronization
        ack_flag(int): flag denoting acknowledgement
        window_size(int): size of congestion window
        source_ip: source IP address (optional)
        dest_ip: destination IP address (optional)
        input_tcp_header: tcp header that's been packed already (optional)
        data: data to add len of within header (optional)
    Returns:
        TCP header packed
    """
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        seq_num,
        ack_num,
        IP_HEADER_LENGTH << 4,
        (syn_flag << 1) | ack_flag,
        window_size,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton("127.0.0.1"),
        socket.inet_aton("127.0.0.1"),
        0,
        TCP_PROTOCOL,
        len(tcp_header),
    )
    checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = (
        struct.pack(
            "!HHLLBBH",
            source_port,
            destination_port,
            seq_num,
            ack_num,
            IP_HEADER_LENGTH << 4,
            (syn_flag << 1) | ack_flag,
        )
        + struct.pack("H", checksum)
        + struct.pack("!H", window_size)
    )

    # Create a tcp_header with a checksum based on input values
    if input_tcp_header and data and source_ip and dest_ip:
        source_addr = socket.inet_aton(source_ip)
        dest_addr = socket.inet_aton(dest_ip)
        len_of_header = len(tcp_header) + len(data)

        packet = struct.pack(
            "!4s4sBBH", source_addr, dest_addr, 0, TCP_PROTOCOL, len_of_header
        )
        packet += packet + tcp_header + data

        checksum = calculate_checksum(packet)

        tcp_header = struct.pack
        tcp_header = (
            struct.pack(
                "!HHLLBBH",
                source_port,
                destination_port,
                seq_num,
                ack_num,
                IP_HEADER_LENGTH << 4,
                (syn_flag << 1) | ack_flag,
                TCP_WINDOW_SIZE,
            )
            + struct.pack("H", checksum)
            + struct.pack("!H", window_size)
        )
        return tcp_header

    return tcp_header


def make_ip_header(src_ip, dest_ip, protocol, data=""):
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
    header = header[:10] + struct.pack("!H", checksum) + header[12:]

    return header
