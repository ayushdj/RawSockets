# RawSockets

## High Level Approach

The high level approach, which can be followed within `main` of `rawhttpget.py`, goes as follows:

- Create an instance of the `MyRawSocket` class
- Get the IP addresses for the source machine and the host of the request URL
- Create a random port to use on the local machine for the sockets to bind
- Parse the filename given the request URL as well as the path given the URL
- Perform the TCP handshake
  - Send a SYN from the local machine to the host
  - Receive an ACK from the server, if the packet from server doesn't have the right information, retry the SYN send.
- Following the handshake, send the HTTP request packet to the server and then
  read the packets in from the socket that have been received from the HTTP
  server. Followed by sorting the packets and then subsequently writing them
  into a file on the source machine.

## TCP/IP Features Implemented

- Checksum validation of packets, and adding checksums to TCP headers
- TCP three-way handshake
- TCP connection teardown
- Basic 1 minute timeout functionality for handshake
- Receival of out of order packets, just needing to sort them in a map
  - ignoring duplicate packets through nature of map data structure
- Creation of IP headers with unique IDs

## Challenges Faced

The biggest challenge was understanding how to implement the handshake.
Initially we experienced issues with the flags appearing in tcpdump out of
order. Such as [S] [.] [S.]...

We were able to rectify the issue and move on to the HTTP request portion which
also brought its own set of challenges. We were unable to get back 200 codes
and after some trial and error realized that the path we were requesting from
was incorrect. After this was solved it was just a matter of thinking of a data
structure to use for storing the received packets and how to handle them being
out of order. A dictionary made this easy as we used the key as the seq number
for the packet then sorted it in order to write the file properly.

We did not manage to implement the congestion control, however.

## Who Worked on What

### Ayush

- Setup the MyRawSocket class
- wrote the handshake methods
- methods for pulling data from the received packets
- Helped write the main method flow in rawhttpget.py

### Matt

- Wrote the `utils.py` file
- helper methods for parsing, creating headers, writing file
- Wrote IP address parsing in MyRawSocket class
- Wrote the main method code and CLI parsing in rawhttpget.py

