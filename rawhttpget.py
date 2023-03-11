#!/usr/bin/env python3
import argparse

from RawSocket import MyRawSocket


def main(url):
    print(f"Input url is: {url}")
    raw_socket = MyRawSocket()


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
