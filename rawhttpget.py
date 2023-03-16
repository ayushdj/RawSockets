#!/usr/bin/env python3
import argparse
import os
import random
import sys
import urllib.parse

from RawSocket import MyRawSocket
from utils import determine_destination_ip_address, get_filename


def main(url):
    os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    # create the instance of the raw socket
    raw_socket = MyRawSocket()

    # extract the source and destination IP addresses
    source_ip_address = raw_socket.determine_local_host_ip_address()
    destination_ip_address = determine_destination_ip_address(url)
    source_port = random.randint(1000, 65565)
    # Monitor tcpdump with: sudo tcpdump -vv -n host 204.44.192.60, can use this too
    raw_socket.send_syn(source_ip_address, destination_ip_address, source_port)

    tcp_header = raw_socket.receive_synack(
        source_ip_address, destination_ip_address, source_port
    )

    raw_socket.send_ack(
        source_port, source_ip_address, destination_ip_address, tcp_header
    )

    file_pointer, path_to_file = get_filename(urllib.parse.urlsplit(url))
    raw_socket.request_for_resource(
        source_ip_address,
        destination_ip_address,
        source_port,
        tcp_header,
        raw_socket.determine_url_host(url),
        path_to_file,
    )

    raw_socket.download_file(
        source_ip_address, destination_ip_address, source_port, file_pointer
     )
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
