#!/usr/bin/env python3
import argparse
import os
import random
import sys
import urllib.parse

from RawSocket import MyRawSocket
from utils import determine_destination_ip_address, determine_filename_and_path, generate_random_source_port

# Monitor tcpdump with: sudo tcpdump -vv -n host 204.44.192.60
def main(url):
    os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    # create the instance of the raw socket
    raw_socket = MyRawSocket()

    # extract the source and destination IP addresses, along with
    # creating a random port number
    source_ip_address = raw_socket.my_current_ip_address()
    destination_ip_address = determine_destination_ip_address(url)
    source_port = generate_random_source_port()

    file_pointer, path_to_desired_file = determine_filename_and_path(urllib.parse.urlsplit(url))
    
    # before doing anything, we need to perform the handshake, so we do that here.
    # we also get the unpacked tcp header from the source, so we can pass it along
    # in our subsequent communications 
    unpacked_tcp_header_from_server = raw_socket.perform_handshake(source_ip_address=source_ip_address, source_port=source_port, destination_ip_address=destination_ip_address)

    # we want to request a particular resource in the destination_ip_address, so we need to 
    # make a GET request.
    raw_socket.request_for_and_download_file(source_ip_address,source_port,destination_ip_address,url,path_to_desired_file,unpacked_tcp_header_from_server, file_pointer)

    # raw_socket.download_file(
    #     source_ip_address, destination_ip_address, source_port, file_pointer
    # )
    raw_socket.close_sockets()
    sys.exit()


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
