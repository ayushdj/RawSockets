#!/usr/bin/env python3

import argparse
import re


def main(url):
    print(f'Input url is: {url}')
    print(f'Hostname is: {parse_host(url)}')


# Extract the hostname from the URL
def parse_host(url: str) -> str:
    hostname_re = r'https?://([^/]+)'
    hostname = re.match(hostname_re, url).group(1)
    return hostname

if __name__ == '__main__':
    # Define the command line arguments
    parser = argparse.ArgumentParser(description='Perform a raw HTTP GET')
    parser.add_argument('url', metavar='URL', type=str, help='The URL to make a GET request to.')

    # Parse the arguments
    args = parser.parse_args()

    # Call the main method with the specified URL
    main(args.url)
