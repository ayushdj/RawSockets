# Utility functions to aid with networking operations.

import struct

from helper import IP_HEADER_LENGTH, IP_LENGTH_OFFSET, IP_VERSION, TCP_PROTOCOL

CLRF = '\r\n\r\n'


def calculate_checksum(message):
    '''
    Calculate the checksum of the given message.

    Args:
            message: characters to calculate checksum for.
    Returns:
            checksum: integer checksum value
    '''
    # If the length of the message is odd, pad with a zero byte
    if len(message) % 2 != 0:
            message += b'\0'
    # Calculate the one's complement sum of the message contents
    s = sum(struct.unpack('!{}H'.format(len(message)//2), message))
    # Fold the 32-bit sum into 16 bits by adding the carry bits
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    # Take the one's complement of the result
    checksum = (~s) & 0xFFFF
    return checksum


def write_file(file, response_dict: dict):
    '''
    Write the response from a dictionary to a file.

    Args:
            file: file pointer
        response_dict(dict): dictionary mapping int to strings as parts of response.
    '''
    response = ''.join([response_dict.get(key) for key in sorted(response_dict)])
    # Make sure valid HTTP Response Code
    if response.find('200 OK') < 0:
            print('[ERROR]: Invalid HTTP Response Code')
        sys.exit()
    # Write the response to the file if valid response code.
    with open(file, 'w') as write_file:
            ordered_seq = sorted(response_dict.iterkeys())
            for idx, element in enumerate(ordered_seq):
                    if idx == 0:
                            write_file.writelines(response_dict[element].split(CLRF)[1])
                write_file.writelines(response_dict[element])

# Define function to create TCP segment
def make_tcp_header(
                source_port,
                destination_port,
                seq_num,
                ack_num,
                syn_flag,
                ack_flag,
                window_size
):
        '''
        Generate TCP header.

        Args:
                source_port(int): source port
                destination_port(int): destination port
                seq_num(int): number within packet sequence
                ack_num(int): acknowledgement number 
                syn_flag(int): flag denoting synchronization
                ack_flag(int): flag denoting acknowledgement
                window_size(int): size of congestion window
        Returns:
            TCP header packed
        '''
        tcp_header = struct.pack('!HHLLBBHHH', source_port, destination_port, seq_num, ack_num, IP_HEADER_LENGTH << 4,
                                 (syn_flag << 1) | ack_flag, TCP_WINDOW_SIZE, 0, window_size)
        pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'), 0,
                                    TCP_PROTOCOL, len(tcp_header))
        checksum = calculate_checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack('!HHLLBBH', source_port, destination_port, seq_num, ack_num, IP_HEADER_LENGTH << 4,
                                 (syn_flag << 1) | ack_flag, TCP_WINDOW_SIZE) + struct.pack('H',
                                                                                            checksum) + struct.pack(
                                                                                                    '!H', window_size)
        return tcp_header

<<<<<<< HEAD

=======
>>>>>>> bc520f50a01b633185658cbdd8622c4b8940a96f
def make_ip_header(src_ip, dest_ip, protocol, data):
    '''
    Generate IP header.

    Args:
        src_ip: source IP address
        dest_ip: destination IP address
        protocol: network protocol to use
        data: used for adding len of data to header
    Returns
        IP header packed
    '''
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
        checksum = calculate_checksum(header)

        # replace the placeholder value with the actual checksum
        header = header[:10] + struct.pack('!H', checksum) + header[12:]

        return header
