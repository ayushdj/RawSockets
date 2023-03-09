# Utility functions to aid with networking operations.

import struct

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
    # Write the response to the file if valid code.
    write_file = open(file, "w")
    ordered_seq = sorted(response_dict.iterkeys())
    for idx, element in enumerate(ordered_seq):
        if idx == 0:
            write_file.writelines(response_dict[element].split(CLRF)[1])
        write_file.writelines(response_dict[element])
