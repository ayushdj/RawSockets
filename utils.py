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


def create_tcp_header_with_checksum(
    tcp_header,
    src_port,
    seq,
    ackno,
    fin_flag,
    syn_flag,
    rst_flag,
    psh_flag,
    ack_flag,
    source_ip,
    dest_ip,
    data,
):
    TCP_SOURCE = src_port
    TCP_DEST = 80
    TCP_SEQ = seq
    TCP_ACK_SEQ = ackno
    TCP_DOFF = 5
    # tcp flags
    TCP_FIN = fin_flag
    TCP_SYN = syn_flag
    TCP_RST = rst_flag
    TCP_PSH = psh_flag
    TCP_ACK = ack_flag
    TCP_URG = 0
    TCP_WINDOW = socket.htons(5840)  # maximum allowed window size
    TCP_CHECKSUM = 0
    TCP_URG_PTR = 0
    TCP_OFFSET_RES = (TCP_DOFF << 4) + 0
    TCP_FLAGS = (
        TCP_FIN
        + (TCP_SYN << 1)
        + (TCP_RST << 2)
        + (TCP_PSH << 3)
        + (TCP_ACK << 4)
        + (TCP_URG << 5)
    )

    request_data = data
    # pseudo header fields
    s_addr = socket.inet_aton(source_ip)
    d_addr = socket.inet_aton(dest_ip)
    placehold = 0
    used_prtcl = socket.IPPROTO_TCP
    length_of_tcp = len(tcp_header) + len(request_data)

    # packing the packet
    packet_maker = struct.pack(
        "!4s4sBBH", s_addr, d_addr, placehold, used_prtcl, length_of_tcp
    )
    packet_maker = packet_maker + tcp_header + bytes(request_data, "utf-8")

    TCP_CHECKSUM = calculate_checksum(packet_maker)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = (
        struct.pack(
            "!HHLLBBH",
            TCP_SOURCE,
            TCP_DEST,
            TCP_SEQ,
            TCP_ACK_SEQ,
            TCP_OFFSET_RES,
            TCP_FLAGS,
            TCP_WINDOW,
        )
        + struct.pack("H", TCP_CHECKSUM)
        + struct.pack("!H", TCP_URG_PTR)
    )
    return tcp_header


def make_ip_header(id, src_ip, dest_ip, data="") -> bytes:
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
    # tos = 0
    # total_len = len(data)  # + IP_LENGTH_OFFSET
    # fragmentation_offset = 0
    # ip_ttl = 255
    # checksum = 0
    # src_ip_num = socket.inet_aton(str(src_ip))
    # dest_ip_num = socket.inet_aton(dest_ip)

    # header = struct.pack(
    #     "!BBHHHBBH4s4s",
    #     (IP_VERSION << 4) + IP_HEADER_LENGTH,
    #     tos,
    #     total_len,
    #     id,
    #     fragmentation_offset,
    #     ip_ttl,
    #     TCP_PROTOCOL,
    #     checksum,
    #     src_ip_num,
    #     dest_ip_num,
    # )

    # return header
    IP_HEADER_LEN = 5
    IP_VERSION = 4
    IP_TYPE_OF_SERVICE = 0
    IP_TOTAL_LENGTH = 0
    IP_ID = id
    IP_FRAGMENTAION_OFFSET = 0
    IP_TTL = 255
    IP_PROTOCOL = socket.IPPROTO_TCP
    IP_CHECKSUM = 0
    IP_SRC_ADDR = socket.inet_aton(src_ip)
    IP_DST_ADDR = socket.inet_aton(str(dest_ip))
    IP_IHL_VER = (IP_VERSION << 4) + IP_HEADER_LEN
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        IP_IHL_VER,
        IP_TYPE_OF_SERVICE,
        IP_TOTAL_LENGTH,
        IP_ID,
        IP_FRAGMENTAION_OFFSET,
        IP_TTL,
        IP_PROTOCOL,
        IP_CHECKSUM,
        IP_SRC_ADDR,
        IP_DST_ADDR,
    )
    return ip_header


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
    filename = ""
    path_url = ""
    if not url.path:
        filename = "index.html"

    if url.path[-1] == "/":
        path_url = "/"
        filename = "index.html"
    else:
        url = url.path
        split_name = url.rsplit("/", 1)
        filename = split_name[1]
    return filename, path_url
