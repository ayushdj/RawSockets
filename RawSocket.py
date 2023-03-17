import socket
import struct
import time
import urllib.parse

from utils import *

# IP constants
# IP_VERSION = 4
# IP_HEADER_LENGTH = 5
# IP_HEADER_SIZE = IP_HEADER_LENGTH * 4
# IP_TTL = 255
# IP_LENGTH_OFFSET = 20

# TCP constants
# TCP_WINDOW_SIZE = 1024
# TCP_TIMEOUT = 1
# WINDOW_SIZE = 4
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

    def close_sockets(self):
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

        # send the syn message
        self._send_syn(source_ip_address, source_port, destination_ip_address)

        unpacked_tcp_header = self._receive_synack(source_ip_address, source_port, destination_ip_address)

        return unpacked_tcp_header

    def _send_syn(self, source_ip_address, source_port, destination_ip_address) -> None:
        """
        Create and send syn message.

        Args:
            source_ip_address: source IP address
            source_port: source port
            destination_ip_address: destination IP address
        """
        # set the flags
        flags = [0,0,0,0,1]

        # make IP header and tcp header, and then add them together to be sent as part of 1 singular packet
        packet_to_be_sent = construct_ip_header(42069, source_ip_address, destination_ip_address) + make_tcp_header(flags, source_port, 0, 0, source_ip_address, destination_ip_address)
        self.sending_socket.sendto(packet_to_be_sent, (destination_ip_address, 0))

        self.timer = time.time()

    def _receive_synack(self, source_ip_address, source_port, destination_ip_address):
        """
        Receive a SYNACK from the server.
        """
        
        # extract the packet from the server and then unpack that packet
        packet_from_server, _ = self.receiving_socket.recvfrom(BUFFER_LENGTH)
        unpacked_ip_header_from_server = struct.unpack("!BBHHHBBH4s4s", packet_from_server[:20])

        # now extract the tcp header and actually unpack it
        ip_version_and_header_length, _, _, _, _, _, _, _, source_ip_address_from_server, destination_ip_address_from_server = unpacked_ip_header_from_server
        actual_ip_header_length = (ip_version_and_header_length & 0xF) * 4

        tcp_header_from_server = packet_from_server[actual_ip_header_length : actual_ip_header_length + 20]
        unpacked_tcp_header_from_server = struct.unpack("!HHLLBBHHH", tcp_header_from_server)

        # get the source ip and destination ip from the server
        source_ip_information = unpacked_ip_header_from_server[8]
        destination_ip_information = unpacked_ip_header_from_server[9]

        # extract the IP address for both the destination and the source from the server.
        source_ip_address_from_server = socket.inet_ntoa(source_ip_information)
        destination_ip_address_from_server = socket.inet_ntoa(destination_ip_information)
                
        if (
            destination_ip_address_from_server == source_ip_address and
            source_ip_address_from_server == destination_ip_address
            and unpacked_tcp_header_from_server[5] == 18
            and source_port == unpacked_tcp_header_from_server[1]
            and ((self.timer - time.time()) < 60)
        ):
            self._send_acknowledgement(unpacked_tcp_header_from_server, source_ip_address=source_ip_address, source_port=source_port, destination_ip_address=destination_ip_address)
        else:
            print("ENTERED HERE")
            self._send_syn(source_ip_address, source_port, destination_ip_address)
        return unpacked_tcp_header_from_server

    def _send_acknowledgement(self, unpacked_tcp_header, source_ip_address, source_port, destination_ip_address):
        """
        Send ACK message from us.

        Args:
            unpacked_tcp_header: the tcp header we get from the receive_synack function
            source_ip_address: source IP address 
            source_port (int): source port
            destination_ip_address: destination IP address
        """

        # set the flags and construct the packet that needs to be sent as an acknowledgement
        flags = [0, 0, 1, 0, 0]
        ack_pack_to_be_sent = construct_ip_header(42070, source_ip_address, destination_ip_address) + make_tcp_header(flags, source_port, unpacked_tcp_header[3], unpacked_tcp_header[2] + 1, source_ip_address, destination_ip_address)

        self.sending_socket.sendto(ack_pack_to_be_sent, (destination_ip_address, 0))


    def my_current_ip_address(self):
        """
            Helper method to determine the IP address of the source (i.e. us)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port_number = 80
        sock.connect(("www.ccs.neu.edu", port_number))
        sock_name = sock.getsockname()
        ip = sock_name[0]
        string_ip = str(ip)
        return string_ip

    def request_for_resource_in_server(self,source_ip_address,source_port,destination_ip_address,host_name,path,unpacked_tcp_header):
        """
        Send a request to the resource that located in the server

        Args:
            source_ip_address: source IP address 
            source_port: source port
            destination_ip_address: destination IP address
            host_name: name of the host
            path: the path of the file
            unpacked_tcp_header: the unpacked header we got when we did the handshake
        """
        # set the flags
        flags = [1, 0, 1, 0, 0]

        # create the request
        http_request = f"GET {path} HTTP/1.0\r\nHOST: {host_name}"
        http_request += CLRF

        if len(http_request) % 2 != 0:
            http_request += " "

        # send the data over
        self.sending_socket.sendto(construct_ip_header(42071, source_ip_address, destination_ip_address) + make_tcp_header(flags,source_port,unpacked_tcp_header[3],unpacked_tcp_header[2] + 1,source_ip_address,destination_ip_address, http_request.encode())  + http_request.encode(), (destination_ip_address, 0))
        print("SENT REQUEST")

    def download_file(self, source_ip, dest_ip, src_port, fp):
        response_dictionary = {}
        c = 0
        while True:
            # receiving packet from the server
            received_packet = self.receiving_socket.recvfrom(BUFFER_LENGTH)
            # packet string from tuple
            received_packet = received_packet[0]
            # take first 20 characters for the ip header
            ip_header = received_packet[0:20]
            # unpacking the packet
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            src_addr = socket.inet_ntoa(iph[8])
            tcp_header = received_packet[iph_length : iph_length + 20]
            # unpacking the packet
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)

            # src_port = tcph[0]
            dest_port = tcph[1]
            seq_number = tcph[2]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            h_size = iph_length + tcph_length * 4
            data_size = len(received_packet) - h_size
            print(f"{dest_port} == {src_port}")
            print(f"{src_addr} == {dest_ip}")
            print(f"{data_size} > 0")
            if dest_port == src_port and src_addr == dest_ip and data_size > 0:
                print("inside first if statement")
                c += 1
                # get data from the packet
                data = received_packet[h_size:]
                # storing the sequence of packets
                response_dictionary[seq_number] = data
                # packet for teardown initiation
                teardown_initiator = ""

                ip_header = construct_ip_header(54322, source_ip, dest_ip)

                # tcp header fields
                tcp_source = src_port  # source port
                tcp_seq = tcph[3]
                tcp_ack_seq = seq_number + data_size
                # tcp flags
                tcp_fin = 0
                tcp_syn = 0
                tcp_rst = 0
                tcp_psh = 0
                tcp_ack = 1

                data_for_teardown = ""
                tcp_header = make_tcp_header(
                    tcp_source,
                    tcp_seq,
                    tcp_ack_seq,
                    tcp_fin,
                    tcp_syn,
                    tcp_rst,
                    tcp_psh,
                    tcp_ack,
                )
                tcp_header = make_tcp_header_with_checksum(
                    tcp_source,
                    tcp_seq,
                    tcp_ack_seq,
                    tcp_fin,
                    tcp_syn,
                    tcp_rst,
                    tcp_psh,
                    tcp_ack,
                    tcp_header=tcp_header,
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    data=data_for_teardown.encode(),
                )

                # final full packet - syn packets dont have any data
                teardown_initiator = ip_header + tcp_header + data_for_teardown.encode()
                self.sending_socket.sendto(teardown_initiator, (dest_ip, 0))

            if (
                (tcph[5] == 17 or tcph[5] == 25)
                and dest_port == src_port
                and src_addr == dest_ip
                and data_size == 0
            ):
                print("finito")
                # finish the connection
                # data to be sent during finishing the connection
                fin_packet = ""
                ip_header = construct_ip_header(54322, source_ip, dest_ip)

                # tcp header fields
                tcp_source = src_port  # source port
                tcp_seq = tcph[3]
                tcp_ack_seq = seq_number + 1
                # tcp flags
                tcp_fin = 1
                tcp_syn = 0
                tcp_rst = 0
                tcp_psh = 0
                tcp_ack = 1

                # data to be sent in final packet
                data_in_finpacket = ""

                tcp_header = make_tcp_header(
                    tcp_source,
                    tcp_seq,
                    tcp_ack_seq,
                    tcp_fin,
                    tcp_syn,
                    tcp_rst,
                    tcp_psh,
                    tcp_ack,
                )
                tcp_header = make_tcp_header_with_checksum(
                    tcp_source,
                    tcp_seq,
                    tcp_ack_seq,
                    tcp_fin,
                    tcp_syn,
                    tcp_rst,
                    tcp_psh,
                    tcp_ack,
                    tcp_header=tcp_header,
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    data=data_in_finpacket.encode(),
                )

                # final full packet - syn packets dont have any data
                fin_packet = ip_header + tcp_header + data_in_finpacket.encode()
                self.sending_socket.sendto(fin_packet, (dest_ip, 0))
                print("bouta write file")
                write_file(fp, response_dictionary)
                break
            elif (
                dest_port == src_port
                and src_addr == dest_ip
                and data_size == 0
                and c > 0
            ):
                print("bouta write file")
                write_file(fp, response_dictionary)
                break
