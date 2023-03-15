CS5700 Project 4 Raw socket

In this file, you should briefly describe your high-level approach, what TCP/IP features you implemented, and any challenges you faced. You must also include a detailed description of which student worked on which part of the code.

High-level Approach
1. Create 2 raw sockets to send and receive packets
    self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    ip packets requirements:
    Your program must implement all features of IP packets. 
    This includes 
    - [ ]validating the checksums of incoming packets, 
    - [ ]and setting the correct version, header length and total length, protocol identifier, and checksum in each outgoing packet.
    - [ ]Obviously, you will also need to correctly set the source and destination IP in each outgoing packet. 
    - [ ]Furthermore, your code must be defensive, i.e. you must check the validity of IP headers from the remote server. Is the remote IP                        correct? Is the checksum correct? Does the protocol identifier match the contents of the encapsulated header?

    tcp packets requirements:
    - [ ]Your program must verify the checksums of incoming TCP packets, and generate correct checksums for outgoing packets. 
    - [ ]Your code must select a valid local port to send traffic on, perform the three-way handshake, and correctly handle connection teardown. 
    - [ ]Your code must correctly handle sequence and acknowledgement numbers. Your code may manage the advertised window as you see fit. 
    - [ ]Your code must include basic timeout functionality: if a packet is not ACKed within 1 minute, assume the packet is lost and retransmit it. 
    - [ ]Your code must be able to receive out-of-order incoming packets and put them back into the correct order before delivering them to the                  higher-level, HTTP handling code. 
    - [ ]Your code should identify and discard duplicate packets. Finally, your code must implement a basic congestion window: your code should start with cwnd=1, and increment the cwnd after each succesful ACK, up to a fixed maximum of 1000 (e.g. cwnd must be <=1000 at all times). If your program observes a packet drop or a timeout, reset the cwnd to 1.
    - [ ]As with IP, your code must be defensive: check to ensure that all incoming packets have valid checksums and in-order sequence numbers. If your program does not receive any data from the remote server for three minutes, your program can assume that the connection has failed. In this case, your program can simply print an error message and close.

    Define a checksum calculation function 

2. Make IP Header and calculate checksum 
    source_ip = local ip address from my machine (vm may be different)
    dest_ip = 192.168.1.24(i.e. http://david.choffnes.com/classes/cs5700f22/2MB.log)

    > reference: https://www.binarytides.com/raw-socket-programming-in-python-linux/  
        # ip header fields

3. Make TCP Segment/TCP header, calculate checksum, set and update sequence number. 
    The TCP protocol uses a sequence number to keep track of the data being transmitted between two endpoints. The sender assigns a unique sequence number to each segment it sends, and the receiver uses these sequence numbers to reconstruct the original data.
    To update the sequence number in the TCP segment, you should keep track of the last sequence number sent and increment it by the number of bytes sent in each subsequent segment. You can do this by adding the length of the data being sent to the previous sequence number.

    For example, if you sent a segment with sequence number 1000 and 500 bytes of data, the next segment you send should have a sequence number of 1500.
    > reference: https://www.binarytides.com/raw-socket-programming-in-python-linux/  
        # tcp header fields

4. Pack a network packet use struct.pack() (A packet = Ip header + Tcp header + data)
    Define functions to verify ip header checksum and tcp segment checksum 
    Be defensive: 
    Requirement in project description: i.e. you must check the validity of IP headers from the remote server. Is the remote IP correct? Is the checksum correct? Does the protocol identifier match the contents of the encapsulated header? 

5. Send the first network packet with **tcp flag SYN** to initiate the three-way handshake
    **verify checksum in IP and TCP headers** before sending the packet.
    > references: https://en.wikipedia.org/wiki/Transmission_Control_Protocol
        TCP segment structure Flags (8 bits)

6. Receive **the SYN-ACK packet** from the server and **verify checksum in IP and TCP headers** on the received packet
    Check the received packet TCP fragement flag field. 

7. Send the ACK packet to complete the three-way handshake -- **connection established**

    Based on the established TCP connection, create a TCP segment and send it using send socket 
    (To send data, you should create a TCP segment with the appropriate source and destination port numbers, sequence number, and acknowledgement number, along with any data you wish to send. You should also set the appropriate TCP flags, such as the PSH and ACK flags, depending on the purpose of the segment.)

    Continuously listen for incoming TCP segments on the socket you opened for receiving. 
    When a segment arrives, you should check its sequence number and acknowledgement number to make sure it is part of the established TCP connection. 
    If the segment is valid, you can extract any data it contains and process it accordingly.

8. Download HTML content in the destination IP address.
    1. Send an HTTP request to the server asking for the HTML content. The HTTP request should include the appropriate headers and request method (usually GET).
    2. Receive the HTML content from the server. This can be done by reading data from the socket until the full content is received.
    3. If the HTML content is large, it may be sent in multiple segments. In this case, the server will include a "Content-Length" header in the response to indicate the total length of the content. You should read data from the socket until you have received the entire content as indicated by the Content-Length header.
    4. If the HTML content is too large to fit into a single read from the socket, you may need to implement a loop to read the content in chunks until the entire content is received.
    5. Once the HTML content has been received, you can parse it to extract the information you need.
    6. Close the TCP connection by sending a FIN packet to the server, and waiting for the server to acknowledge the FIN packet with an ACK packet.

9. Other requirements in setting file name, print error msg if http status code is not 200

TCP/IP Features Implemented




Challenges

Collaboration
