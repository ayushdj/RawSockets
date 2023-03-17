import socket
import struct
import time
import urllib.parse

from utils import *

BUFFER_LENGTH = 65565


class MyRawSocket:
    """
    Defines a custom implementation for a raw socket
    """

    def __init__(self):
        # Create 2 sockets - one for sending the raw data, one for receiving TCP data
        self.sending_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        self.receiving_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )

        self.timer = None

        self.acknowledgement_flags = [0, 0, 1, 0, 0]
        self.syn_flags = [0, 0, 0, 0, 1]
        self.resource_request_flags = [1, 0, 1, 0, 0]

    def close_sockets(self):
        """
        Closes both sockets.
        """
        self.sending_socket.close()
        self.receiving_socket.close()

    def determine_url_host(self, url):
        """
        Helper function to determine the URL of the host
        """
        splitted_url = urllib.parse.urlsplit(url)
        actual_host = splitted_url.netloc
        return actual_host
    
    def perform_handshake(self, source_ip_address, source_port, destination_ip_address):
        """
        This function conducts the handshake.

        Args:
            source_ip_address: source IP address
            source_port: source port
            destination_ip_address: destination IP address
        """

        # send the syn message
        self._send_syn_to_server(source_ip_address, source_port, destination_ip_address)

        # receive the packet from the server and deconstruct it and return the unpacked tcp header
        return self._receive_synack_from_server(source_ip_address, source_port, destination_ip_address)

    def request_for_and_download_resource(self, source_ip_address,source_port,destination_ip_address,url,path_to_file,unpacked_tcp_header_from_server, name_of_file):
        """
        This function requests for and downloads the file we want.

        Args:
            source_ip_address: source IP address
            source_port: source port
            destination_ip_address: destination IP address
            url: the url of the source
            path_to_file: the path to the file that we want
            unpacked_tcp_header_from_server: the unpacked_tcp_header_from_server from the destination
            name_of_file: the name of the file we wish to create
        """

        # request for the resource in the server
        self._request_for_resource_in_server(source_ip_address, source_port, destination_ip_address, self.determine_url_host(url), path_to_file, unpacked_tcp_header_from_server)

        self._get_packets_and_create_file(name_of_file, source_ip_address, source_port, destination_ip_address)



    def _send_syn_to_server(self, source_ip_address, source_port, destination_ip_address) -> None:
        """
        Create and send syn message.

        Args:
            source_ip_address: source IP address
            source_port: source port
            destination_ip_address: destination IP address
        """

        # make IP header and tcp header, and then add them together to be sent as part of 1 singular packet
        self._send_a_packet_to_server(construct_IPV4_header(42069, source_ip_address, destination_ip_address) + develop_TCP_header(self.syn_flags, source_port, 0, 0, source_ip_address, destination_ip_address), destination_ip_address=destination_ip_address)

        # start a timer/reset it so that we can actually re-send the syn if we don't get a syn-ack from the server
        self.timer = time.time()

    def _receive_synack_from_server(self, source_ip_address, source_port, destination_ip_address):
        """
        Receive a SYNACK from the server.

        Args:
            source_ip_address: source IP address 
            source_port (int): source port
            destination_ip_address: destination IP address
        """
        # extract the packet from the server and then unpack that packet
        packet_from_server, _ = self.receiving_socket.recvfrom(BUFFER_LENGTH)

        unpacked_ip_header_from_server, unpacked_tcp_header_from_server, _, _ = self._extract_packet_data_from_server(packet_from_server)

        # extract the IP address for both the destination and the source from the server.
        source_ip_address_from_server = socket.inet_ntoa(unpacked_ip_header_from_server[8])
        destination_ip_address_from_server = socket.inet_ntoa(unpacked_ip_header_from_server[9])
        
        # if we haven't gotten a syn-ack from the server within the time designated, or if the IP addresses don't match,
        # then we send another syn to the server.
        if not (
            ((self.timer - time.time()) < 60) and unpacked_tcp_header_from_server[5] == 18 and source_ip_address_from_server == destination_ip_address and
            unpacked_tcp_header_from_server[5] == 18 and destination_ip_address_from_server == source_ip_address and source_port == unpacked_tcp_header_from_server[1]
        ):
            print("ENTERED HERE")
            self._send_syn_to_server(source_ip_address, source_port, destination_ip_address)
        else:
            self._send_acknowledgement(unpacked_tcp_header_from_server, source_ip_address=source_ip_address, source_port=source_port, destination_ip_address=destination_ip_address)

        return unpacked_tcp_header_from_server

    def _send_acknowledgement(self, unpacked_tcp_header_from_server, source_ip_address, source_port, destination_ip_address):
        """
        Send ACK message from us.

        Args:
            unpacked_tcp_header_from_server: the tcp header we get from the receive_synack function
            source_ip_address: source IP address 
            source_port (int): source port
            destination_ip_address: destination IP address
        """        
        # sending the acknowledgement packet
        self._send_a_packet_to_server(construct_IPV4_header(42070, source_ip_address, destination_ip_address) + develop_TCP_header(self.acknowledgement_flags, source_port, unpacked_tcp_header_from_server[3], unpacked_tcp_header_from_server[2] + 1, source_ip_address, destination_ip_address), destination_ip_address=destination_ip_address)


    def my_current_ip_address(self, host):
        """
        Helper function to determine the IP address of the source (i.e. us)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port_number = 80
        sock.connect((host, port_number))
        my_ip_address = sock.getsockname()[0]
        sock.close()
        return str(my_ip_address)

    def _request_for_resource_in_server(self,source_ip_address,source_port,destination_ip_address,host_name,path,unpacked_tcp_header_from_server):
        """
        Send a request to the resource that located in the server

        Args:
            source_ip_address: source IP address 
            source_port: source port
            destination_ip_address: destination IP address
            host_name: name of the host
            path: the path of the file
            unpacked_tcp_header_from_server: the unpacked header we got when we did the handshake
        """
        
        # create the request string
        http_request = f"GET {path} HTTP/1.0\r\nHOST: {host_name}"
        http_request += CLRF

        if len(http_request) % 2 != 0:
            http_request += " "

        # send the request out
        self._send_a_packet_to_server(construct_IPV4_header(42071, source_ip_address, destination_ip_address) + develop_TCP_header(self.resource_request_flags,source_port,unpacked_tcp_header_from_server[3],unpacked_tcp_header_from_server[2] + 1,source_ip_address,destination_ip_address, http_request.encode())  + http_request.encode(), destination_ip_address=destination_ip_address)
        print("SENT REQUEST")
    
    def _send_a_packet_to_server(self, packet_to_be_sent, destination_ip_address) -> None:
        """
            Helper method to send a packet over to the server

            Args:
                packet_to_be_sent: the packet we want to send
                destination_ip_address: the IP of the destination
        """
        # call upon the sending socket to send a packet out
        self.sending_socket.sendto(packet_to_be_sent, (destination_ip_address, 0))

    def _get_packets_and_create_file(self, name_of_file, source_ip_address, source_port, destination_ip_address):
        """
        Helper method to get all the data and then create the desired file

        Args:

            name_of_file: the name of the file we want to create
            source_ip_address: the ip address of the source (i.e. us)
            source_port: the source port
            destination_ip_address: the ip address of the destination
        """
        # This is the result that will be populated with the TCP segments from the server
        data_from_server = {}

        # endlessly loop until we get all the data
        while 1:
            # extract the packet from the server and then unpack that packet to give us IP and TCP data
            packet_from_server, _ = self.receiving_socket.recvfrom(BUFFER_LENGTH)
            unpacked_ip_header_from_server, unpacked_tcp_header_from_server, actual_ip_header_length, actual_tcp_header_length = self._extract_packet_data_from_server(packet_from_server)

            # actual_size_of_data = abs((actual_ip_header_length + actual_tcp_header_length * 4) - len(packet_from_server))

            if unpacked_tcp_header_from_server[1] == source_port \
                and socket.inet_ntoa(unpacked_ip_header_from_server[8]) == destination_ip_address:

                # if we have more data to receive from the server, then we keep constructing the result
                if abs((actual_ip_header_length + actual_tcp_header_length * 4) - len(packet_from_server)) > 0:
                    print("WE ENTERED THE FIRST IF STATEMENT IN DOWNLOAD")

                    # populate the data
                    data_from_server[unpacked_tcp_header_from_server[2]] = packet_from_server[(actual_ip_header_length + actual_tcp_header_length * 4):]

                    # create the flags and send another packet to the server asking for more data
                    self._send_a_packet_to_server(construct_IPV4_header(42070, source_ip_address, destination_ip_address) + develop_TCP_header(self.acknowledgement_flags,source_port,unpacked_tcp_header_from_server[3],unpacked_tcp_header_from_server[2]+ abs((actual_ip_header_length + actual_tcp_header_length * 4) - len(packet_from_server)),source_ip_address,destination_ip_address), destination_ip_address=destination_ip_address)

                # if we have gotten all the data, then we save the response
                elif unpacked_tcp_header_from_server[5] in (17, 25):
                    save_response_from_server(name_of_file, data_from_server)
                    return
                else:
                    continue

    def _extract_packet_data_from_server(self, packet_from_server):
        """
        Helper method to help unpack the IP header coming from the server and TCP header as well.

        Args:
            packet_from_server: the packet we want to receive from the server
        """

        # unpack the IP Header from the server and also get the IP header length
        unpacked_ip_header_from_server = struct.unpack("!BBHHHBBH4s4s", packet_from_server[:20])
        ip_version_and_header_length, _, _, _, _, _, _, _, source_ip_address_from_server, destination_ip_address_from_server = unpacked_ip_header_from_server
        actual_ip_header_length = (ip_version_and_header_length & 0xF) * 4

        # now unpack the TCP header from the IP header, and also get the length of the TCP header
        tcp_header_from_server = packet_from_server[actual_ip_header_length : actual_ip_header_length + 20]
        unpacked_tcp_header_from_server = struct.unpack("!HHLLBBHHH", tcp_header_from_server)
        actual_tcp_header_length = unpacked_tcp_header_from_server[4] >> 4

        # return all the information
        return unpacked_ip_header_from_server, unpacked_tcp_header_from_server, actual_ip_header_length, actual_tcp_header_length