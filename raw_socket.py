import socket

# Create a raw socket using the IP protocol
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Set the IP header included in the packet
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Bind the socket to a network interface
s.bind(('192.168.1.100', 0))

# Create a TCP header
source_port = 1234
dest_port = 80
sequence = 0
acknowledgement = 0
offset = 5
tcp_flags = 0b00010  # SYN flag
window_size = socket.htons(8192)
checksum = 0
urgent_pointer = 0
tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, sequence,
                         acknowledgement, offset << 4, tcp_flags, window_size,
                         checksum, urgent_pointer)

# Create an IP header
source_ip = '192.168.1.100'
dest_ip = '8.8.8.8'
ip_version = 4
header_length = 5
tos = 0
total_length = 20 + len(tcp_header)
identification = 54321
flags = 0b0000
fragment_offset = 0
ttl = 255
protocol = socket.IPPROTO_TCP
checksum = 0
src_ip = socket.inet_aton(source_ip)
dst_ip = socket.inet_aton(dest_ip)
ip_header = struct.pack('!BBHHHBBH4s4s', (ip_version << 4) + header_length, tos,
                        total_length, identification, (flags << 13) + fragment_offset,
                        ttl, protocol, checksum, src_ip, dst_ip)

# Combine the headers and payload into a single packet
packet = ip_header + tcp_header + b'Hello, world!'

# Send the packet
s.sendto(packet, (dest_ip, 0))

