import socket
import struct
import time
import urllib.parse

from utils import *

# IP constants
IP_VERSION = 4
IP_HEADER_LENGTH = 5
IP_HEADER_SIZE = IP_HEADER_LENGTH * 4
IP_TTL = 255
IP_LENGTH_OFFSET = 20

# TCP constants
TCP_WINDOW_SIZE = 1024
TCP_TIMEOUT = 1
WINDOW_SIZE = 4
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

    def close_sockets(self):
        self.sending_socket.close()
        self.receiving_socket.close()

    def determine_url_host(self, url):
        """
        Helper function to determine the URL of the
        """
        splitted_url = urllib.parse.urlsplit(url)
        actual_host = splitted_url.netloc
        return actual_host

    def send_syn(self, source_ip, dest_ip, source_port) -> None:
        """
        Create and send syn message.

        Args:
            source_ip: source IP address
            dest_ip: destination IP address
            source_port: source port
        """
        # make IP header
        ip_header = make_ip_header(54321, source_ip, dest_ip)

        # Make initial TCP header
        tcp_header = make_tcp_header(source_port, 0, 0, 0, 1, 0, 0, 0)
        tcp_header = make_tcp_header_with_checksum(
            source_port,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            tcp_header=tcp_header,
            source_ip=source_ip,
            dest_ip=dest_ip,
        )

        # final full packet - syn packets dont have any data
        sending_packet = ip_header + tcp_header

        # Send the packet finally - the port specified has no effect
        self.sending_socket.sendto(sending_packet, (dest_ip, 0))

        # To keep track of packets to be resent
        global start_time
        start_time = time.time()

        # # Send the packet
        # self.sending_socket.sendto(ip_header + tcp_header, (dest_ip, 0))
        # # Record the time at which SYN is starting
        # self.syn_start_time = time.time()

    def send_ack(self, src_port, source_ip, dest_ip, tcph):
        """
        Send ACK message.

        Args:
            source_ip: source IP address
            dest_ip: destination IP address
            source_port (int): source port
            tcp_header (bytes): tcp headers
        """
        # ip_header = make_ip_header(54322, source_ip, dest_ip)
        # tcp_sequence_num = tcp_header[3]
        # tcp_ack_sequence_num = tcp_header[2] + 1  # must increment ack seq number

        # tcp_header = make_tcp_header(
        #     source_port, tcp_sequence_num, tcp_ack_sequence_num, 0, 0, 0, 0, 1
        # )
        # tcp_header = make_tcp_header(
        #     source_port,
        #     tcp_sequence_num,
        #     tcp_ack_sequence_num,
        #     0,
        #     0,
        #     0,
        #     0,
        #     1,
        #     tcp_header=tcp_header,
        #     source_ip=source_ip,
        #     dest_ip=dest_ip,
        #     data=b"",
        # )
        # self.sending_socket.sendto(ip_header + tcp_header, (dest_ip, 0))
        acknowledgement_packet = ""
        # Incrementing the SYN packetId by 1 and sending it out.
        ip_header = make_ip_header(54322, source_ip, dest_ip)
        # tcp header fields
        tcp_source_port = src_port  # source port
        tcp_seq = tcph[3]
        tcp_ack_seq = tcph[2] + 1
        # tcp flags
        tcp_fin = 0
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 1

        # the ! in the pack format string means network order
        tcp_header = make_tcp_header(
            tcp_source_port,
            tcp_seq,
            tcp_ack_seq,
            tcp_fin,
            tcp_syn,
            tcp_rst,
            tcp_psh,
            tcp_ack,
        )
        tcp_header = make_tcp_header_with_checksum(
            tcp_source_port,
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
        )
        acknowledgement_packet = ip_header + tcp_header

        self.sending_socket.sendto(acknowledgement_packet, (dest_ip, 0))

    def receive_synack(self, source_ip, dest_ip, src_port):
        """
        Receive a SYNACK from the server.
        """
        # packet = self.receiving_socket.recvfrom(BUFFER_LENGTH)[0]
        # ip_header_unpack = struct.unpack("!BBHHHBBH4s4s", packet[:20])
        # header_len = ip_header_unpack[0] & 0xF
        # address_dest = socket.inet_ntoa(ip_header_unpack[8])
        # address_source = socket.inet_ntoa(ip_header_unpack[9])
        # tcp_header = packet[header_len * 4 : header_len * 4 + 20]
        # tcp_header_unpack = struct.unpack("!HHLLBBHHH", tcp_header)
        #
        # if (
        #     address_source == source_ip
        #     and address_dest == dest_ip
        #     and tcp_header_unpack[5] == 18
        #     and src_port == tcp_header_unpack[1]
        #     and ((self.syn_start_time - time.time()) < 60)
        # ):
        #     print("send_ack called")
        #     print(tcp_header_unpack)
        #     self.send_ack(src_port, source_ip, dest_ip, tcp_header_unpack)
        # else:
        #     print("send_syn called")
        #     self.send_syn(source_ip, dest_ip, src_port)
        # return

        ### OLD IMPLEMENTATION
        # packet = self.receiving_socket.recvfrom(BUFFER_LENGTH)[0]
        # ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])
        # version = (ip_header[0] >> 4) & 0xF
        # ip_header_len = version * 4
        # source_ip_addr = socket.inet_ntoa(ip_header[8])
        # dest_ip_addr = socket.inet_ntoa(ip_header[9])
        # tcp_header = packet[ip_header_len : ip_header_len + 20]
        # tcp_header = struct.unpack("!HHLLBBHHH", tcp_header)

        # print(tcp_header)

        # print(f"Source IP: {source_ip_addr} == {dest_ip}")
        # print(f"Dest IP: {dest_ip_addr} == {source_ip}")
        # print(f"Header 5: {tcp_header[5]} == 18")
        # print(f"Source Port: {src_port} == {tcp_header[1]}")
        # print(f"Time Diff: {self.syn_start_time - time.time()} < 60")

        # if (
        #     source_ip_addr == dest_ip
        #     and dest_ip_addr == source_ip
        #     and tcp_header[5] == 18
        #     and src_port == tcp_header[1]
        #     and self.syn_start_time - time.time() < 60
        # ):
        #     self.send_ack(source_ip, dest_ip, src_port, tcp_header)
        # else:
        #     self.send_syn(source_ip, dest_ip, src_port)
        # return tcp_header
        # starting an infinite loop
        while True:
            received_packet = self.receiving_socket.recvfrom(BUFFER_LENGTH)
            # packet string from tuple
            received_packet = received_packet[0]
            # take first 20 characters for the ip header
            ip_header = received_packet[0:20]
            # now unpack them
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dest_addr = socket.inet_ntoa(iph[9])
            tcp_header = received_packet[iph_length : iph_length + 20]

            # now unpack them
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)

            # src_port = tcph[0]
            dest_port = tcph[1]
            seq_number = tcph[2]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            h_size = iph_length + tcph_length * 4
            data_size = len(received_packet) - h_size
            # get data from the packet
            data = received_packet[h_size:]
            if (
                src_addr == dest_ip
                and dest_addr == source_ip
                and tcph[5] == 18
                and src_port == tcph[1]
                and ((start_time - time.time()) < 60)
            ):
                self.send_ack(src_port, source_ip, dest_ip, tcph)
                break
            else:
                self.send_syn(source_ip, dest_ip, src_port)
                break
        return tcph

    def determine_local_host_ip_address(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("www.ccs.neu.edu", 80))
            ip = sock.getsockname()[0]
        except socket.error:
            ip = "ERR"
        sock.close()
        return str(ip)

    def request_for_resource(
        self,
        source_ip_address,
        destination_ip_address,
        source_port,
        tcp_header,
        hostname,
        path,
    ):
        ip_header = make_ip_header(54323, source_ip_address, destination_ip_address)
        tcp_header = make_tcp_header(
            source_port, tcp_header[3], tcp_header[2] + 1, 0, 0, 0, 1, 1
        )

        http_request = "".join(
            ["GET ", path, " HTTP/1.1", CLRF, "HOST: ", hostname + CLRF * 2]
        )

        if len(http_request) % 2 != 0:
            http_request += " "

        # src_port, seq, ackno, fin_flag, syn_flag, rst_flag, psh_flag,
        # ack_flag):
        tcp_header = make_tcp_header(
            source_port, tcp_header[3], tcp_header[2] + 1, 0, 0, 0, 1, 1
        )

        tcp_header = make_tcp_header_with_checksum(
            source_port,
            tcp_header[3],
            tcp_header[2] + 1,
            0,
            0,
            0,
            1,
            1,
            tcp_header=tcp_header,
            source_ip=source_ip_address,
            dest_ip=destination_ip_address,
            data=http_request.encode(),
        )

        packet = ip_header + tcp_header + http_request.encode()
        self.sending_socket.sendto(packet, (destination_ip_address, 0))

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

                ip_header = make_ip_header(54322, source_ip, dest_ip)

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
                tcp_header = make_tcp_header(
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
                ip_header = make_ip_header(54322, source_ip, dest_ip)

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
                tcp_header = make_tcp_header(
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
