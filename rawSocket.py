import socket, sys, time
import os
from urllib.parse import urlparse
from struct import *
from random import randint
import time
from collections import namedtuple
from functools import reduce
import array


SYN = 0x02   # 0b00000010
ACK = 0x10   # 0b00010000
SYN_ACK = 0x12   # 0b00010010
FIN = 0x01   # 0b00000001
FIN_ACK = 0x11   # 0b00010001
PSH_ACK = 0x18   # 0b00011000
FIN_PSH_ACK = 0x19 # 0b00011001

class RawSocket:

    def __init__(self, src_ipAddr, dest_ipAddr, src_port, dest_port):
        """
        Initializes an instance of the custom TCP class.

        Parameters
        ----------
        src_ipAddr : str
            Source IP address
        dest_ipAddr : str
            Destination IP address
        src_port : int
            Source port number
        dest_port : int
            Destination port number
        """
        try:
            # Creates two raw sockets for sending and receiving packets.
            self._send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self._recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self._srcIpAddr = src_ipAddr
            self._destIpAddr = dest_ipAddr

            # Set the source and destination port numbers
            self._srcPort = src_port
            self._destPort = dest_port
            
            # Generates a random TCP sequence number within the valid range (i.e., 0 to 2^32-1).
            self._seq = randint(0, (2**32) - 1)
            
            # Sets the initial TCP acknowledgement sequence number to 0.
            self._ack_seq = 0
            self._ip_id = 1

            # Congestion control variables.
            # Sets the initial congestion window size to 1.
            self._maxcwnd = 1000
            self._cwnd = 1
            self._rwnd = 65535

            # Sets the initial TCP advertised window size to 20480 bytes.
            self._adwind = socket.htons(self._rwnd)

            # This is ipv4, so the Maximum Segment Size is 1460 bytes.
            # Must be an even number
            self._mss = 1460
        except socket.error as e:
            # Prints an error message and exits the program if there is an error creating the sockets.
            print("Error: Cannot create a raw socket", e)
            sys.exit(1)
    
        # Prints IP and port number for debugging purposes.
        print('src IP and port:', self._srcIpAddr, self._srcPort)
        print('Dest IP and port:', self._destIpAddr, self._destPort)

    
    def checksum(self, msg):
        """
        Calculate the checksum of the given message.

        The function takes a byte message, iterates over it in pairs of bytes, and computes the checksum using the
        Internet checksum algorithm. The computed checksum is returned as a 16-bit integer.

        Parameters
        ----------
        msg : bytes
            The byte message for which the checksum needs to be calculated.

        Returns
        -------
        int
            The calculated checksum as a 16-bit integer.

        Local Variables
        ---------------
        s : int
            The accumulator for the checksum calculation.
        w : int
            A 16-bit word obtained by combining two consecutive bytes in the message.
        """

        s = 0  # Initialize the accumulator

        # Loop through the message, taking 2 characters (bytes) at a time
        for i in range(0, len(msg), 2):
            w = (msg[i]) + ((msg[i + 1]) << 8)  # Combine two consecutive bytes into a 16-bit word
            s = s + w  # Add the 16-bit word to the accumulator

        # Handle carry-over by adding the most significant 16 bits to the least significant 16 bits
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)

        # Calculate the one's complement and mask the result to a 4-byte short (16 bits)
        s = ~s & 0xffff

        return s  # Return the calculated checksum

    
    def ip_header(self):
        """
        Creates an IP header for the custom TCP implementation.

        Returns
        -------
        ip_header : bytes
            Packed IP header in network byte order
        """
        # IP header fields
        ip_ihl = 5        # IP header length (IHL) in 32-bit words
        ip_ver = 4        # IP version (4 for IPv4)
        ip_tos = 0        # Type of service (0 for default)
        ip_tot_len = 0    # Total length of the IP packet (0 for auto-calculation)
        ip_id = self._ip_id  # IP identification (unique ID for each packet)
        self._ip_id += 1
        self._ip_id %= 65536
        ip_frag_off = 0   # Fragment offset (0 for not fragmented)
        ip_ttl = 255      # Time to live (TTL)
        ip_proto = socket.IPPROTO_TCP  # Protocol (TCP)
        ip_check = 0      # Checksum (0 for auto-calculation)
        ip_saddr = socket.inet_aton(self._srcIpAddr)  # Source IP address
        ip_daddr = socket.inet_aton(self._destIpAddr)  # Destination IP address
        ip_ihl_ver = (ip_ver << 4) + ip_ihl  # Combined IP version and header length

        # Pack IP header fields into a bytes object in network byte order
        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

        return ip_header

            
    def tcp_header(self, flags, user_data):
        """
        Creates a TCP header for the custom TCP implementation.

        Parameters
        ----------
        flags : int
            TCP flags (e.g., SYN, ACK, FIN) to be set in the header
        user_data : bytes
            Payload data to be sent with the TCP segment

        Returns
        -------
        tcp_header : bytes
            Packed TCP header in network byte order
        """
        # TCP header fields
        tcp_src = self._srcPort      # Source port
        tcp_dest = self._destPort    # Destination port
        tcp_seq = self._seq          # Sequence number
        tcp_ack_seq = self._ack_seq  # Acknowledgment sequence number
        tcp_doff = 5    # Data offset - 4-bit field, size of TCP header in 32-bit words, 5 * 4 = 20 bytes
        tcp_flags = flags  # TCP flags
        tcp_window = self._adwind  # Maximum allowed window size
        tcp_check = 0      # Checksum (to be calculated later)
        tcp_urg_ptr = 0    # Urgent pointer (not used)

        tcp_offset_res = (tcp_doff << 4) + 0  # Combined data offset and reserved bits

        # Pack initial TCP header fields into a bytes object in network byte order
        tcp_header = pack('!HHLLBBHHH', tcp_src, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        # Pseudo header fields
        src_address = socket.inet_aton(self._srcIpAddr)
        dest_address = socket.inet_aton(self._destIpAddr)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)

        # Create the pseudo header
        psh = pack('!4s4sBBH', src_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header + user_data

        # Calculate the correct checksum
        tcp_check = self.checksum(psh)

        # Repack the TCP header with the correct checksum (not in network byte order)
        tcp_header = pack('!HHLLBBH', tcp_src, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

        return tcp_header


    def _send_one(self, flags, data=""):
        """
        Sends a single TCP segment with the specified flags and data.

        Parameters
        ----------
        flags : int
            TCP flags (e.g., SYN, ACK, FIN) to be set in the header
        data : str, optional
            Payload data to be sent with the TCP segment (default is an empty string)

        """
        # Encode the payload data as bytes
        data = data.encode()

        # Create the IP header
        ip_header = self.ip_header()

        # Create the TCP header with the specified flags and data
        tcp_header = self.tcp_header(flags, data)

        # Combine the IP header, TCP header, and data into a single packet
        packet = ip_header + tcp_header + data

        # Send the packet using the raw send socket
        self._send_socket.sendto(packet, (self._destIpAddr, self._destPort))


    def send(self, data):
        """
        Sends the given data using the TCP protocol.

        Parameters
        ----------
        data : str
            The data to be sent
        """
        # Initialize the advertised window size
        adwnd = 65535

        # Split the data into segments based on the Maximum Segment Size (MSS)
        segments = [data[i:i+self._mss] for i in range(0, len(data), self._mss)]

        # Initialize the buffer for storing the data segments and their sequence numbers
        buffer = {}
        buffer_key = self._seq

        # Fill the buffer with data segments and their sequence numbers
        for data in segments:
            if len(data) % 2 == 1:
                data += " "
            buffer[buffer_key] = data
            buffer_key += len(data)

        # Keep sending data until the buffer is empty
        while self._seq < buffer_key:
            # Calculate the window size based on the congestion window and advertised window
            window_size = min(self._cwnd, adwnd // self._mss)

            # Send packets within the window size
            for i in range(window_size):
                if self._seq not in buffer:
                    window_size = i
                    break
                data = buffer[self._seq]
                self._send_one(flags=PSH_ACK, data=data)
                self._seq += len(data)

            # Receive ACKs for the sent packets
            slow_flag = False
            cur_ack_seq = -1
            for i in range(window_size):
                # Receive a TCP datagram and check its flags
                tcp_datagram = self._receive_one(timeout=5)

                if not tcp_datagram:
                    # If no datagram received, set the slow flag
                    slow_flag = True
                    break
                elif tcp_datagram.flags & ACK == ACK:
                    # Update the advertised window and current acknowledgement sequence number
                    adwnd = min(65535, tcp_datagram.adwind)
                    if tcp_datagram.ack_seq < cur_ack_seq:
                        slow_flag = True
                    else:
                        cur_ack_seq = tcp_datagram.ack_seq
                elif tcp_datagram.flags & FIN == FIN:
                    # Acknowledge the received FIN packet and close the connection
                    self._ack_seq += 1
                    self._send_one(flags=ACK, data="")
                    connection_closed = True
                    break

            # Update the sequence number and congestion control variables
            self._seq = cur_ack_seq
            self.update_congestion_control(slow_flag)


    def update_congestion_control(self, slow_flag):
        """
        Updates the congestion control window size based on the slow_flag.

        Parameters
        ----------
        slow_flag : bool
            A flag indicating whether the transmission is experiencing slow start or congestion
        """
        # If slow_flag is not set, then update the congestion window based on the additive increase
        if not slow_flag:
            # Double the congestion window if it's less than half the maximum congestion window size
            if self._cwnd * 2 <= self._maxcwnd:
                self._cwnd *= 2
            # If the congestion window is more than half the maximum size, increment it by 1
            elif self._cwnd < self._maxcwnd:
                self._cwnd += 1
        # If slow_flag is set, reset the congestion window to 1 for slow start
        else:
            self._cwnd = 1


    def _check_incoming_packets(self, packet):
        """
        Validates the incoming packet by checking the source and destination IP addresses,
        source and destination ports, and IP and TCP checksums.

        Parameters
        ----------
        packet : bytes
            The raw packet received

        Returns
        -------
        bool
            True if the packet passes all validation checks, False otherwise
        """
        # Verify the IP checksum of the received packet
        if not self.verify_ipv4_checksum(packet):
            return False

        # Verify the TCP checksum of the received packet
        if not self.verify_tcp_checksum(packet):
            return False

        # Extract the IP and TCP headers from the packet
        ip_datagram = self.unpack_ip_packet(packet)
        tcp_datagram = self.unpack_tcp_packet(packet)

        # Check if the source and destination IP addresses in the packet match the expected values
        if ip_datagram.src_address != self._destIpAddr or ip_datagram.dest_address != self._srcIpAddr:
            # print("Invalid ip address")
            return False

        # Check if the source and destination ports in the packet match the expected values
        if tcp_datagram.src_port != self._destPort or tcp_datagram.dest_port != self._srcPort:
            # print("Invalid port")
            return False

        # All checks passed, return True
        return True


    def _receive_one(self, timeout=60, size=65535):
        """
        Receives a single packet from the socket, checks its validity, and returns the TCP datagram
        if the packet is valid.

        Parameters
        ----------
        timeout : int, optional
            The socket timeout in seconds, by default 60
        size : int, optional
            The maximum number of bytes to receive, by default 65535

        Returns
        -------
        TCPDatagram or None
            The TCP datagram if a valid packet is received, None otherwise or if the socket times out
        """
        try:
            # Set the socket timeout
            self._recv_socket.settimeout(timeout)

            # Receive the packet from the socket
            received_pkt = self._recv_socket.recv(size)

            # If the received packet is empty, return None
            if len(received_pkt) == 0:
                return None

            # Check the validity of the received packet
            if self._check_incoming_packets(received_pkt):
                # Unpack the IP and TCP headers from the received packet
                ip_datagram = self.unpack_ip_packet(received_pkt)
                tcp_datagram = self.unpack_tcp_packet(received_pkt)

                # Return the TCP datagram if the packet is valid
                return tcp_datagram

        # If the socket times out, return None
        except socket.timeout:
            return None


    def receive_all(self):
        """
        Receives all incoming packets and combines them into a single payload.
        
        Returns
        -------
        tuple
            A tuple containing the HTTP header and the body of the received payload
        """
        # Initialize the buffer for storing received packets
        buffer = None
        # Save the current acknowledgement sequence number as the starting sequence
        start_seq = self._ack_seq

        # Call the _receive_all() method to receive all packets and store them in the buffer
        buffer = self._receive_all()

        # Initialize a list for storing the received data
        received_data = []

        # Iterate through the buffer using the sequence numbers
        while start_seq in buffer:
            # Append the data from the buffer to the received_data list
            received_data.append(buffer[start_seq])

            # Increment the start_seq by the length of the received data segment
            start_seq += len(buffer[start_seq])

        # Combine the received data segments into a single payload
        total_payload = b''.join(received_data)

        # Separate the HTTP header and the body of the payload
        header, _, body = total_payload.partition(b'\r\n\r\n')

        # Return the header and body as a tuple
        return header, body

        
    def _receive_all(self, buffer_limit = 65535):
        """
        Receive all incoming packets and store them in a buffer.

        Parameters
        ----------
        buffer_limit : int, optional
            The maximum buffer size, by default 65535

        Returns
        -------
        dict
            A dictionary containing the received data segments with their sequence numbers as keys
        """
        # Initialize the buffer, buffer_size, start_seq, and data_is_complete_seq
        buffer = {}
        buffer_size = 0

        start_seq = self._ack_seq
        
        data_is_complete_seq = 0x100000000 + 1

        # Initialize the duplicate ACK counter and timeout counter
        dup_ack_counter = 0
        timeout_counter = 0
        max_timeouts = 3
        max_dup = 3

        receive_FIN = False

        # Main loop to receive and process incoming packets
        while not receive_FIN or data_is_complete_seq != self._ack_seq:

            tcp_datagram = self._receive_one()

            if tcp_datagram is None:
                timeout_counter += 1
                self._send_one(ACK, "") 
                if timeout_counter >= max_timeouts:
                    print("Time out, close connection")
                    self.close()
                    return buffer
                continue
            else:
                timeout_counter = 0
                
            if tcp_datagram.ack_seq != self._seq:
                continue

            if tcp_datagram.flags & FIN == FIN:
                payload_len = len(tcp_datagram.payload)
                if payload_len != 0:
                    buffer[tcp_datagram.seq] = tcp_datagram.payload 
                buffer_size += payload_len
                # Reset the duplicate ACK counter
                receive_FIN = True
                data_is_complete_seq = tcp_datagram.seq + payload_len

            # Duplicate packet received
            elif tcp_datagram.seq < self._ack_seq or self._ack_seq in buffer:  
                dup_ack_counter += 1
                if dup_ack_counter >= max_dup:  # Send duplicate ACK for fast retransmit
                    self._send_one(ACK, "")
                    # Reset the duplicate ACK counter
                    dup_ack_counter = 0

            # Store valid packets in buffer: both in order or out of order
            elif self._ack_seq <= tcp_datagram.seq <= self._ack_seq + buffer_limit:
                payload_len = len(tcp_datagram.payload)
                if payload_len != 0:
                    buffer[tcp_datagram.seq] = tcp_datagram.payload 
                buffer_size += payload_len
                # Reset the duplicate ACK counter
                dup_ack_counter = 0

            # Update ack_seq and send messge to server
            while self._ack_seq in buffer and self._ack_seq < data_is_complete_seq:
                payload = buffer[self._ack_seq]
                payload_len = len(payload)
                buffer_size -= payload_len
                self._ack_seq += payload_len
                self._ack_seq %= 0x100000000
                self._rwnd = max(1, buffer_limit - buffer_size)
                self._send_one(ACK, "") 

        # Finalize the connection by sending ACK and FIN_ACK packets
        self._ack_seq += 1
        self._send_one(ACK, "")
        self._send_one(FIN_ACK, "")
        self._receive_one()
        # Return the buffer containing received data segments
        return buffer

    def unpack_ip_packet(self, packet):
        """
        Unpack an IP packet and extract the header information.

        Parameters
        ----------
        packet : bytes
            The raw IP packet bytes

        Returns
        -------
        namedtuple
            A named tuple containing the IP header fields
        """
        # Unpack the IP header and extract relevant fields
        IpHeader = namedtuple('IpHeader', ['version', 'header_length', 'ttl', 'protocol', 'src_address', 'dest_address'])

        ip_header = unpack('!BBHHHBBH4s4s', packet[:20])
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_address = socket.inet_ntoa(ip_header[8])
        dest_address = socket.inet_ntoa(ip_header[9])

        # Return the IP header as a namedtuple
        return IpHeader(version, header_length, ttl, protocol, src_address, dest_address)

    def unpack_tcp_packet(self, packet):
        """
        Unpack a TCP packet and extract the header information.

        Parameters
        ----------
        packet : bytes
            The raw TCP packet bytes

        Returns
        -------
        namedtuple
            A named tuple containing the TCP header fields
        """
        # Unpack the TCP header and extract relevant fields
        TcpHeader = namedtuple('TcpHeader', ['src_port', 'dest_port', 'seq', 'ack_seq', 'header_length', 'flags', 'window_size', 'checksum', 'urgent_pointer', 'payload', 'adwind'])

        tcp_header = unpack('!HHLLBBHHH', packet[20:40])
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence_number = tcp_header[2]
        acknowledgement_number = tcp_header[3]
        header_length = (tcp_header[4] >> 4) * 4
        flags = tcp_header[5]
        window_size = tcp_header[6]
        checksum = tcp_header[7]
        urgent_pointer = tcp_header[8]
        payload = packet[20 + header_length:]
        adwind = socket.ntohs(tcp_header[6])

        # Return the TCP header as a namedtuple
        return TcpHeader(src_port, dest_port, sequence_number, acknowledgement_number, header_length, flags, window_size, checksum, urgent_pointer, payload, adwind)

    def handshake(self):
        """
        Perform the TCP handshake with the server.

        Returns
        -------
        bool
            True if the handshake is successful, False otherwise
        """
        # Perform the 3-way handshake
        # send self.seq = 0
        self._send_one(SYN, "")
        # self.seq += 1
        self._seq += 1
        # Expected server,seq = random server.ack = self.seq
        tcp_datagram = self._receive_one(60)
        if tcp_datagram != None and tcp_datagram.ack_seq == self._seq and tcp_datagram.flags == SYN_ACK:
            # send sefl.seq, self.ack = server.seq + 1
            self._ack_seq = tcp_datagram.seq + 1
            self._send_one(ACK, "")
            print("Connected")
            return True
        print("Connect failed")
        # Return the result of the handshake
        return False

    def close(self):
        """
        Close the connection with the server by sending a FIN packet and waiting for the FIN_ACK response.
        """
        # Send FIN packet to the server
        self._send_one(FIN, "")

        # Wait for FIN_ACK packet,
        start_time = time.time() 
        tcp_datagram = self._receive_one()

        if tcp_datagram != None and tcp_datagram.flags & FIN_ACK:
            # Server acknowledged the FIN_ACK, break the loop
            self._send_one(ACK, "")

        # Close the send and receive sockets    
        self._send_socket.close()
        self._recv_socket.close()


    def verify_ipv4_checksum(self, byte_packet):
        """
        Verify the IPv4 header checksum.

        Parameters
        ----------
        byte_packet : bytes
            The raw IP packet bytes

        Returns
        -------
        bool
            True if the checksum is valid, False otherwise
        """
        # Validate the IPv4 header and calculate the checksum
        ip_header = byte_packet[:20]  # Extract the IP header from the packet
        received_checksum = unpack('!H', ip_header[10:12])[0]  # Extract the received checksum from the IP header
        ip_header = ip_header[:10] + b'\x00\x00' + ip_header[12:]  # Set the checksum field to 0 in the header

        # Calculate the checksum using the checksum function and compare it to the received checksum
        return self.checksum(ip_header) == received_checksum


    def verify_tcp_checksum(self, bytes_packet):
        """
        Verify the TCP header checksum.

        Parameters
        ----------
        bytes_packet : bytes
            The raw TCP packet bytes

        Returns
        -------
        bool
            True if the checksum is valid, False otherwise
        """
        # Validate the TCP packet and calculate the checksum
        ip_header = bytes_packet[:20]  # Extract the IP header from the packet
        tcp_header_length = (bytes_packet[32] >> 4) * 4  # Calculate the length of the TCP header
        tcp_header = bytes_packet[20:20 + tcp_header_length]  # Extract the TCP header from the packet
        tcp_data = bytes_packet[20 + tcp_header_length:]  # Extract the TCP data from the packet

        received_checksum = unpack('!H', tcp_header[16:18])[0]
        
        # Set the checksum field to 0 in the TCP header
        tcp_header = tcp_header[:16] + b'\x00\x00' + tcp_header[18:]

        # Extract the source and destination IP addresses from the IP header
        src_address = ip_header[12:16]
        dest_address = ip_header[16:20]

        # Create the pseudo header
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(tcp_data)
        psh = pack('!4s4sBBH', src_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header + tcp_data

        # Calculate the checksum using the checksum function and compare it to the received checksum
        return self.checksum(psh) == received_checksum



