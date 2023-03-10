#!/usr/bin/env python3
import argparse

from RawSocket import MyRawSocket
from utils import *


def main(url):
    print(f"Input url is: {url}")

    # to do
    path_to_file = ''

    file_pointer = None

    # create the instance of the raw socket
    raw_socket = MyRawSocket()

    # extract the source and destination IP addresses
    source_ip_address = raw_socket.determin_local_host_ip_address()
    destination_ip_address = determine_destination_ip_address(url)

    raw_socket.send_syn(source_ip_address, destination_ip_address, 3000)

    tcp_header = raw_socket.receive_synack(source_ip_address, destination_ip_address, 3000)

    raw_socket.send_ack(source_ip_address, destination_ip_address, 3000, tcp_header)

    response_dict = raw_socket.request_for_resource(source_ip_address, destination_ip_address, 3000,
                                                    tcp_header, raw_socket.determine_url_host(url), path_to_file)

    write_file(file_pointer, response_dict)
    


if __name__ == "__main__":
    # Define the command line arguments
    parser = argparse.ArgumentParser(description="Perform a raw HTTP GET")
    parser.add_argument(
        "url", metavar="URL", type=str, help="The URL to make a GET request to."
    )

    # Parse the arguments
    args = parser.parse_args()

    # Call the main method with the specified URL
    main(args.url)
