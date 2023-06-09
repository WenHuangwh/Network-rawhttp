# CS5700 Project 4: Raw Socket

## High-level Approach

1. We implemented an object-oriented design paradigm for this project. The RawSocket class is responsible for encapsulation and data integration. It creates two raw sockets to send and receive packets:

    self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    
    The RawSocket class has various attributes for implementing IP and TCP features, as well as functions to send/receive packets, pack/unpack headers, verify checksums, and establish/close IP/TCP connections.

2. The main logic flow is as follows:
    1. Create a raw socket object use the user input url (get host name and destination IP address), a random selected port number, and TCP port number 80, as well as local machine IP address. 
    2. Use the handshake function to establish the connection.
        1. Use _send_one to send the first packet with TCP flag SYN, increase the randomly generated TCP sequence number by 1
        2. Use _receive_one to receive the packet from the server. Check if the packet is valid, the ACK sequence number == TCP sequence number, and the TCP flag == SYN ACK
        3. Use _send_one to send the ACK flag to the server and confirm that connection is established
    3. Send the HTTP GET request to the server, receive the packets, and save them to a log file.
    4. Use a while loop to continuly receive network packets untill the receive packet contains a FIN flag.
    5. Establish some exception handling mechanism to catch the error in initialing a raw socket object, establishing connection, and handling non-200 HTTP status code.

## Brief introduction of RawSocket class:

checksum(msg) - Calculates the checksum of a given byte message using the Internet checksum algorithm and returns the computed checksum as a 16-bit integer.

ip_header() - Creates and returns a packed IPv4 header in network byte order for the custom TCP implementation.

tcp_header(flags, user_data) - Creates and returns a packed TCP header in network byte order for the custom TCP implementation, taking into account the specified flags and payload data.

_send_one(flags, data) - Sends a single TCP segment with the specified flags and data.

send(data) - Sends the given data using the TCP protocol.

update_congestion_control(slow_flag) - Updates the congestion control window size based on the slow_flag.

_check_incoming_packets(packet) - Validates the incoming packet by checking the source and destination IP addresses, source and destination ports, and IP and TCP checksums, returning True if the packet is valid and False otherwise.

_receive_one(timeout, size) - Receives a single packet from the socket, checks its validity, and returns the TCP datagram if the packet is valid, or None otherwise or if the socket times out.

receive_all() - Receives all incoming packets and combines them into a single payload, returning a tuple containing the HTTP header and the body of the received payload.

_receive_all(buffer_limit) - Receives all incoming packets and stores them in a buffer, returning a dictionary containing the received data segments with their sequence numbers as keys.

unpack_ip_packet(packet) - Unpacks an IP packet and extracts the header information, returning a named tuple containing the IP header fields.

unpack_tcp_packet(packet) - Unpacks a TCP packet and extracts the header information, returning a named tuple containing the TCP header fields.

handshake() - Performs the TCP handshake with the server, returning True if the handshake is successful and False otherwise.

close() - Closes the connection with the server by sending a FIN packet and waiting for the FIN_ACK response.

verify_ipv4_checksum(byte_packet) - Verifies the IPv4 header checksum of a given raw IP packet, returning True if the checksum is valid and False otherwise.

verify_tcp_checksum(bytes_packet) - Verifies the TCP header checksum of a given raw TCP packet, returning True if the checksum is valid and False otherwise.


## TCP/IP Features Implemented
1. IP 
    1. Pack the IPv4 packet header in correct order. The header consists of 14 fields: version, Internet Header Length(IHL), DSCP(In this project, it is type of service tos), Explicit Congestion Notification(ECN), Total Length, ID, Flags, Fragement Offset, Time To live, Protocol, Header Checksum, Source IP Address, Destination IP Address, and Options.
    2. Unpack and retrive information from the IPv4 packet header.
    3. Check the IP address, version and other in incoming packets, especially verify the checksum 
2. TCP
    1. Pack the TCP packer header in correct order.
    2. Use a randomly selected port to perform three-way handshake and handle the connection teardown.
    3. Check the sequence number, acknowledge number for incoming TCP packets.
    4. Generate correct checksum for outgoing TCP packets.
    5. Establish a timeout function that automatically retransmit a packet in 1 min
    6. Identify and discard duplicate packets
    7. Implement congestion control using congestion window and slow start
    8. Automatically close the connection after 3 miniutes when not packets is received from the server 


## Challenges
1. Efficient collaboration: One of the main challenges we faced was ensuring efficient collaboration between team members. Having two people work on the same file simultaneously is not an ideal practice. To overcome this issue, we adopted a modularization approach, breaking the project development into smaller tasks or functions. After establishing the three-way handshake, we developed and tested our functions individually and merged the functions instead of files. During team meetings, we tested each other's versions in a virtual machine, discussing potential issues and possible solutions to enhance our collective understanding of the project.

2. Ensuring smooth connection: Maintaining continuous communication between the server and client was extremely challenging. Initially, we encountered difficulties in setting the correct sequence numbers, resulting in numerous retransmissions observed in Wire Shark. Later, we faced issues in closing the connection, and it took some time to determine whether the problem lay in the sender socket not sending the FIN flag correctly or the receiver socket waiting too long to receive or recognize the FIN ACK flag. Additionally, the download speed for 2MB, 5MB, and 10MB files appeared unreasonable, as downloading a 2MB file took the longest time.

3. Testing and developing low-level programs in a virtual machine: Both team members lacked experience with low-level networking, which added to the challenges faced. Setting up the virtual machine environment required multiple steps, such as configuring IP tables, installing tools, and turning off network offloading.

## Collaboration:
    Xiaoyao was mainly responsilble for designing the Raw Socket class and its attributes. She also worked on the assembly of TCP and IP header， taking into account all the required information to ensure accurate packet construction. Moreover, Xiaoyao worked diligently on verifying the integrity of network packets using TCP and IP checksums, as well as other relevant information to maintain the robustness and reliability of the communication. 

    Wen concentrated on developing the core functionality of the Raw Socket class by designing and implementing the receive and send functions. He paid close attention to the various challenges associated with maintaining a stable connection and addressed them by incorporating congestion control mechanisms, timeout handling, and other techniques to improve the overall performance and smoothness of the connection.
