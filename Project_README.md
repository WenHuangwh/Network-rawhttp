CS5700 Project 4 Raw socket

High-level Approach
1. We use object-oriented design program paradigm to design this project implementation. The RawSocket class is used to ensure encapsulation and data integration. We create 2 raw sockets to send and receive packets:
    self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    In the RawSocket class, we define a series of attrbuites to implement IP and TCP features and functions to send/receive one and more packets, pack/unpack headers, verify checksums, and establish/close the IP/TCP connection.

2. The main logic flow is as follows:
    1. Create a raw socket object use the user input url (get host name and destination IP address), a random selected port number, and TCP port number 80, as well as local machine IP address. 
    2. Use the handshake function to establish the connection.
        1. Use _send_one to send the first packet with TCP flag SYN, increase the randomly generated TCP sequence number by 1
        2. Use _receive_one to receive the packet from the server. Check if the packet is valid, the ACK sequence number == TCP sequence number, and the TCP flag == SYN ACK
        3. Use _send_one to send the ACK flag to the server and confirm that connection is established
    3. Send the HTTP GET request to the server, receive the packets, and save them to a log file.
    4. Use a while loop to continuly receive network packets untill the receive packet contains a FIN flag.
    5. Establish some exception handling mechanism to catch the error in initialing a raw socket object, establishing connection, and handling non-200 HTTP status code.

TCP/IP Features Implemented
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


Challenges:
    1. Efficient collaboration: One of the main challenges we faced was ensuring efficient collaboration between team members. Having two people work on the same file simultaneously is not an ideal practice. To overcome this issue, we adopted a modularization approach, breaking the project development into smaller tasks or functions. After establishing the three-way handshake, we developed and tested our functions individually and merged the functions instead of files. During team meetings, we tested each other's versions in a virtual machine, discussing potential issues and possible solutions to enhance our collective understanding of the project.
    2. Ensuring smooth connection: Maintaining continuous communication between the server and client was extremely challenging. Initially, we encountered difficulties in setting the correct sequence numbers, resulting in numerous retransmissions observed in Wire Shark. Later, we faced issues in closing the connection, and it took some time to determine whether the problem lay in the sender socket not sending the FIN flag correctly or the receiver socket waiting too long to receive or recognize the FIN ACK flag. Additionally, the download speed for 2MB, 5MB, and 10MB files appeared unreasonable, as downloading a 2MB file took the longest time.
    3. Testing and developing low-level programs in a virtual machine: Both team members lacked experience with low-level networking, which added to the challenges faced. Setting up the virtual machine environment required multiple steps, such as configuring IP tables, installing tools, and turning off network offloading.

Collaboration
    Xiaoyao was mainly responsilble for designing the Raw Socket class and its attributes. She also worked on the assembly of TCP and IP header， taking into account all the required information to ensure accurate packet construction. Moreover, Xiaoyao worked diligently on verifying the integrity of network packets using TCP and IP checksums, as well as other relevant information to maintain the robustness and reliability of the communication.
    Wen concentrated on developing the core functionality of the Raw Socket class by designing and implementing the receive and send functions. He paid close attention to the various challenges associated with maintaining a stable connection and addressed them by incorporating congestion control mechanisms, timeout handling, and other techniques to improve the overall performance and smoothness of the connection.
