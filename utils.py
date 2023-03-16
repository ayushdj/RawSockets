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
TCP_DEST_PORT = 80
TCP_DATA_OFFSET = 5
MAX_WINDOW_SIZE = 5840

def calculate_checksum(message):
    # if the message length is odd, add a null byte at the end
    if len(message) % 2 != 0:
        message += 0x00

    # initialize the checksum to zero
    checksum = 0

    # iterate over every 16-bit chunk of the message
    for i in range(0, len(message), 2):
        # combine the two bytes into a 16-bit integer
        word = message[i] + (message[i+1] << 8)
        # add the 16-bit integer to the checksum
        checksum += word
        # wrap the checksum if it overflows
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # take the one's complement of the checksum
    checksum = ~checksum & 0xFFFF

    return checksum


def ccalculate_checksum(message):
    """
    Calculate the checksum of the given message.

    Args:
         message: characters to calculate checksum for.
    Returns:
        checksum: integer checksum value
    """
    # Initialize checksum to 0
    checksum = 0

    # For every 2 bytes, fold together with leftshift of 8 to make 8byte
    for i in range(0, len(message), 2):
        fold = message[i] + (message[i + 1] << 8)
        checksum += fold

    # Fold 32 bit sum into 16 bit
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum << 16
    # Take one's complement
    checksum = ~checksum & 0xFFFF
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
        print(f"opened: {file}")
        ordered_seq = sorted(response_dict.keys())
        for idx, element in enumerate(ordered_seq):
            if idx == 0:
                write_file.writelines(response_dict[element].split(CLRF)[1])
            write_file.writelines(response_dict[element])
        print(f"Done writing file at: {file}")


def make_tcp_header(
    src_port,
    sequence_num,
    ack_num,
    finish_flag,
    syn_flag,
    reset_flag,
    push_flag,
    ack_flag,
) -> bytes:
    """
    Make a TCP header and return the packed bytes.
    Flags Reference: https://www.site24x7.com/learn/linux/tcp-flags.html

    Args:

    Returns:
        tcp_header as packed bytes
    """
    tcp_urg_ptr = 0
    window = socket.htons(MAX_WINDOW_SIZE)
    checksum = 0
    tcp_offset = (TCP_DATA_OFFSET << 4) + 0
    # Pack all the flags into one using shift
    flags = (
        finish_flag
        + (syn_flag << 1)
        + (reset_flag << 2)
        + (push_flag << 3)
        + (ack_flag << 4)
        + (tcp_urg_ptr << 5)
    )
    return struct.pack(
        "!HHLLBBHHH",
        src_port,
        TCP_DEST_PORT,
        sequence_num,
        ack_num,
        tcp_offset,
        flags,
        window,
        checksum,
        tcp_urg_ptr,
    )


def make_tcp_header_with_checksum(
    src_port,
    sequence_num,
    ack_num,
    finish_flag,
    syn_flag,
    reset_flag,
    push_flag,
    ack_flag,
    tcp_header=None,
    source_ip=None,
    dest_ip=None,
    data=b"",
) -> bytes:
    """
    Make a TCP header also including the checksum for the passed in the TCP header.
    Flags Reference: https://www.site24x7.com/learn/linux/tcp-flags.html

    Args:
        src_port (int): port of source
        sequence_num (int): number in sequence
        ack_num (int): acknowledgement number
        finish_flag (int): determines if finished
        reset_flag (int): determines whether to drop connection and reset
        push_flag (int): determines if this header is pushing data
        ack_flag (int): determines acknowledgement
        tcp_header (bytes): passed in tcp_header to calculate the checksum for (optional)
        source_ip: IP address of source (optional)
        dest_ip: IP address of destination (optional)
        data (bytes): data to be included in the request (optional)

    Returns:
        tcp_header as packed bytes including the checksum
    """
    # Verify args have been passed in properly
    if not tcp_header or not source_ip or not dest_ip:
        print(
            f"[ERROR]: missing parameters for tcp_header | source_ip | dest_ip. Found {tcp_header}, {source_ip}, and {dest_ip}"
        )
        sys.exit()

    tcp_urg_ptr = 0
    window = socket.htons(MAX_WINDOW_SIZE)
    checksum = 0
    tcp_offset = (TCP_DATA_OFFSET << 4) + 0
    # Pack all the flags into one using shift
    flags = (
        finish_flag
        + (syn_flag << 1)
        + (reset_flag << 2)
        + (push_flag << 3)
        + (ack_flag << 4)
        + (tcp_urg_ptr << 5)
    )

    # Extract the source/dest IP addresses as bytes
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)

    # Create the packet
    packet = (
        struct.pack(
            "!4s4sBBH",
            source_address,
            dest_address,
            0,
            TCP_PROTOCOL,
            len(tcp_header) + len(data),
        )
        + tcp_header
        + data
    )

    # Return the tcp_header packed
    return (
        struct.pack(
            "!HHLLBBH",
            src_port,
            TCP_DEST_PORT,
            sequence_num,
            ack_num,
            tcp_offset,
            flags,
            window,
        )
        + struct.pack("H", calculate_checksum(packet))
        + struct.pack("!H", tcp_urg_ptr)
    )


def make_ip_header(id, src_ip, dest_ip, data=b"") -> bytes:
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
    return struct.pack(
        "!BBHHHBBH4s4s",
        (IP_VERSION << 4) + IP_HEADER_LENGTH,
        0,                                      # type of service
        len(data) + IP_LENGTH_OFFSET,           # size
        id,                                     # packet id
        0,                                      # fragmentation offset
        255,                                    # Time to live
        TCP_PROTOCOL,
        0,                                      # checksum
        socket.inet_aton(src_ip),               # source IP as bytes
        socket.inet_aton(dest_ip),              # destination IP as bytes
    )


def determine_destination_ip_address(url):
    returned_tuple = urllib.parse.urlparse(url)
    host_name = returned_tuple.hostname
    destnation_ip_address = socket.gethostbyname(host_name)
    return destnation_ip_address


def get_filename(url) -> tuple:
    """
    Extract the filename and path given a URL.

    Args:
        url: url from urllib.parse.
    Returns:
        tuple: filename and the path of the url.
    """
    # Set defaults
    file_path = "/"
    file_name = "index.html"

    if url.path != "/":
        file_path = url.path
        if url.path[-1] != "/":
            file_name = url.path.rsplit("/", 1)[1]

    return file_name, file_path
