# Utility functions to aid with networking operations.

import socket
import struct
import urllib.parse
import random


CLRF = "\r\n\r\n"

MAX_WINDOW_SIZE = 5840


def calculate_checksum(message):
    """
    Calculate the checksum of the given message.

    Args:
         message: characters to calculate checksum for.
    Returns:
        checksum: integer checksum value
    """
    # if the message length is odd, add a null byte at the end
    if len(message) % 2 != 0:
        message += b"\x00"

    # initialize the checksum to zero
    checksum = 0

    # iterate over every 16-bit chunk of the message
    for i in range(0, len(message), 2):
        # combine the two bytes into a 16-bit integer
        left_shift = message[i + 1] << 8
        word = message[i] + left_shift
        # add the 16-bit integer to the checksum
        checksum += word
        # wrap the checksum if it overflows
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # take the one's complement of the checksum and return it
    return ~checksum & 0xFFFF


def save_response_from_server(name_of_file, data_from_server):
    arr = []

    # sort the keys due to the offset nature of receiving data
    for seq in sorted(data_from_server.keys()):
        arr.extend(bytearray(data_from_server[seq]))
    byte_converted_array = bytearray(arr)

    # if we get a 200 response from the first element of the bytearray, then we can
    # proceed
    if byte_converted_array.startswith(bytearray("HTTP/1.1 200 OK", "utf-8")):
        with open(name_of_file, "wb") as new_output_file:
            new_output_file.write(
                data_from_server[sorted(data_from_server.keys())[0]].split(
                    CLRF.encode()
                )[1]
            )

            # loop over all the data and write it to the file. We've
            # already sorted it.
            for seq in sorted(data_from_server.keys())[1:]:
                new_output_file.write(data_from_server[seq])
            return


def develop_TCP_header(
    flags,
    source_port,
    sequence_number,
    acknowledgement_number,
    source_ip_address,
    destination_ip_address,
    data=b"",
) -> bytes:
    """
    Make a TCP header and return the packed bytes.
    Flags Reference: https://www.site24x7.com/learn/linux/tcp-flags.html

    Args:
        flags: all the TCP flags
        source_port: the source port
        sequence_number: the sequence number
        acknowledgement_number: the ack number
        source_ip_address: the source IP
        destination_ip_address: the destination IP
        data: the data we want to put into the TCP header

    Returns:
        tcp_header as packed bytes
    """
    # create the tuple of flags from the arguments
    flags_tuple = (
        (flags[3] << 2)
        + (flags[2] << 4)
        + (flags[4] << 1)
        + (flags[0] << 3)
        + (flags[1])
        + (0 << 5)
    )

    TCP_header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        80,
        sequence_number,
        acknowledgement_number,
        (5 << 4),
        flags_tuple,
        socket.htons(MAX_WINDOW_SIZE),
        0,
        0,
    )

    packet = (
        struct.pack(
            "!4s4sBBH",
            socket.inet_aton(source_ip_address),
            socket.inet_aton(destination_ip_address),
            0,
            socket.IPPROTO_TCP,
            len(TCP_header) + len(data),
        )
        + TCP_header
        + data
    )

    # return the packet with the checksum calculated for that packet
    return (
        struct.pack(
            "!HHLLBBH",
            source_port,
            80,
            sequence_number,
            acknowledgement_number,
            (5 << 4),
            flags_tuple,
            socket.htons(MAX_WINDOW_SIZE),
        )
        + struct.pack("H", calculate_checksum(packet))
        + struct.pack("!H", 0)
    )


def construct_IPV4_header(
    id, source_ip_address, destination_ip_address, data=b""
) -> bytes:
    """
    Generate IP header.

    Args:
        id: the identifier of the packet
        source_ip_address: source IP address
        destination_ip_address: destination IP address
        data: used for adding len of data to header
    Returns
        IP header packed
    """
    return struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) + 5,
        0,
        len(data) + 20,
        id,
        0,
        255,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(source_ip_address),
        socket.inet_aton(destination_ip_address),
    )


def determine_destination_ip_address(url):
    """
    Helper method to determine the ip address of the destination URL
    """
    returned_tuple = urllib.parse.urlparse(url)
    host_name = returned_tuple.hostname
    destnation_ip_address = socket.gethostbyname(host_name)
    return destnation_ip_address


def get_path_url_to_file(split_url) -> str:
    """
    Determines the path of the file

    Args:
        split_url: the split url
    """
    # if we can get a path, then we do that path other wise we set the
    # path url to "/"
    path_url = split_url.path or "/"
    return path_url


def get_name_of_file(split_url) -> str:
    """
    Get the name of the file we want

    Args:
        split_url: the split url
    """
    path_url = get_path_url_to_file(split_url)
    file_name = (
        "index.html" if path_url.endswith("/") else split_url.path.rsplit("/", 1)[-1]
    )
    return file_name


def generate_random_source_port() -> int:
    """
    generates a random number to be used as the port number.
    Any random number between 1025 and 65536
    """
    return random.randint(1025, 65536)
