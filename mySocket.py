import socket, sys, time
import os
from urllib.parse import urlparse
from struct import *
from random import randint
import time
from collections import namedtuple, deque
from priorityQueue import PriorityQueue
from functools import reduce


SYN = 0x02   # 0b00000010
ACK = 0x10   # 0b00010000
SYN_ACK = 0x12   # 0b00010010
FIN = 0x01   # 0b00000001
FIN_ACK = 0x11   # 0b00010001
PSH_ACK = 0x18   # 0b00011000
FIN_PSH_ACK = 0x19 # 0b00011001

class RawSocket:

    def __init__(self, src_ipAddr, dest_ipAddr, src_port, dest_port, timeout=60):
        try:
            # Creates two raw sockets for sending and receiving packets.
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.recv_socket.settimeout(timeout)
            self._srcIpAddr = src_ipAddr
            self._destIpAddr = dest_ipAddr
            # Choosing a random port number within the dynamic allocation range 
            self._srcPort = src_port
            self._destPort = dest_port
            
            # Generates a random TCP sequence number within the valid range (i.e., 0 to 2^32-1).
            self._seq = randint(0, (2**32) - 1)
            
            # Sets the initial TCP acknowledgement sequence number to 0.
            self._ack_seq = 0

            self.ip_id = 1    
            # Congestion control variables.
            # Sets the initial congestion window size to 1.
            self.cwnd = 1
            self.ssthresh = 65535
            self.rwnd = 65535
            # Sets the initial TCP advertised window size to 20480 bytes.
            self.tcp_adwind = socket.htons (self.rwnd)
            # Sets the initial slow start flag to True, indicating that the congestion avoidance algorithm
            # is in the slow start phase.
            self.slow_start_flag = True
            # This is ipv4 so Maximum Segment Size is 1460 bytes.
            self.mss = 1460
        except socket.error as e:
            # Prints an error message and exits the program if there is an error creating the sockets.
            print("Error: Cannot create a raw socket", e)
            sys.exit(1)
    
        # Prints IP and port number for debugging purposes.
        print('src IP and port:', self._srcIpAddr, self._srcPort)
        print('Dest IP and port:', self._destIpAddr, self._destPort)
    
    # checksum functions needed for calculation checksum
    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = (msg[i]) + ((msg[i+1]) << 8 )
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        return s
    
    def ip_header(self):
        # IP header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0
        ip_id = self.ip_id
        self.ip_id += 1
        self.ip_id %= 65536
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(self._srcIpAddr)
        ip_daddr = socket.inet_aton(self._destIpAddr)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        # print(f"{ip_ihl_ver}, {ip_tos}, {ip_tot_len}, {ip_id}, {ip_frag_off}, {ip_ttl}, {ip_proto}, {ip_check}, {ip_saddr}, {ip_daddr}")
        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        return ip_header
            
    def tcp_header(self, flags, user_data):
        # tcp header fields
        tcp_src = self._srcPort
        tcp_dest = self._destPort
        tcp_seq = self._seq
        tcp_ack_seq = self._ack_seq
        tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_window = self.tcp_adwind	#	maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = flags

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp_src, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

        # pseudo header fields
        src_address = socket.inet_aton( self._srcIpAddr )
        dest_address = socket.inet_aton(self._destIpAddr)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)

        psh = pack('!4s4sBBH' , src_address , dest_address , placeholder , protocol , tcp_length)
        psh = psh + tcp_header + user_data

        tcp_check = self.checksum(psh)

        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , tcp_src, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
        return tcp_header

    def _send_one(self, flags, data=""):
        data = data.encode()
        ip_header = self.ip_header()
        tcp_header = self.tcp_header(flags, data)
        packet = ip_header + tcp_header + data
        self.send_socket.sendto(packet, (self._destIpAddr, self._destPort))


    # def send(self, data):
    #     # Split the data into segments according to the MSS
    #     segments = [data[i:i+self.mss] for i in range(0, len(data), self.mss)]

    #     for segment in segments:
    #         if len(segment) % 2 == 1:
    #             segment += " "
    #         # Send the data segment
    #         self._send_one(PSH_ACK, segment)
    #         self._seq += len(segment)

    #         # Wait for the ACK from the server
    #         while True:
    #             tcp_datagram = self._receive_one()
    #             if tcp_datagram is None:
    #                 continue
    #             # Check if the received packet is an ACK for the current data segment
    #             if tcp_datagram.flags == ACK and tcp_datagram.ack_seq == self._seq:
    #                 # Update the acknowledgement sequence number
    #                 self._ack_seq = tcp_datagram.seq + len(tcp_datagram.payload)
    #                 break
    #             else:
    #                 print("Unexpected packet received. Waiting for ACK...")

    def send(self, data):
        segments = [data[i:i+self.mss] for i in range(0, len(data), self.mss)]

        # Implement a deque to handle segments in flight
        segments_in_flight = deque()

        # Initialize the duplicate ACK counter
        dup_ack_counter = 0

        while segments or segments_in_flight:
            # Send segments within the cwnd limit
            while segments and len(segments_in_flight) < self.cwnd:
                segment = segments.pop(0)
                if len(segment) % 2 == 1:
                    segment += " "
                self._send_one(PSH_ACK, segment)
                self._seq += len(segment)
                segments_in_flight.append((self._seq, segment))

            # Wait for the ACK from the server
            tcp_datagram = self._receive_one(timeout=60)

            if tcp_datagram is None:  # Timeout occurred
                # Timeout handling
                self.ssthresh = max(len(segments_in_flight) // 2, 2)
                self.cwnd = 1
                self.slow_start_flag = True
                dup_ack_counter = 0

                # Resend the first unacknowledged segment
                unacked_seq, unacked_segment = segments_in_flight[0]
                self._send_one(PSH_ACK, unacked_segment)

            elif tcp_datagram.flags == ACK:
                # Check if the received packet is an ACK for a segment in flight
                if any(s[0] == tcp_datagram.ack_seq for s in segments_in_flight):
                    # Update the acknowledgement sequence number
                    self._ack_seq = tcp_datagram.seq + len(tcp_datagram.payload)

                    # Remove acknowledged segments from segments_in_flight
                    segments_in_flight = deque(s for s in segments_in_flight if s[0] > tcp_datagram.ack_seq)

                    # Reset duplicate ACK counter
                    dup_ack_counter = 0

                    # Adjust the cwnd based on slow start or congestion avoidance
                    if self.slow_start_flag:
                        self.cwnd *= 2
                        if self.cwnd >= self.ssthresh:
                            self.slow_start_flag = False
                    else:
                        self.cwnd += 1

                else:  # Duplicate ACK received
                    dup_ack_counter += 1
                    if dup_ack_counter >= 3:  # Fast retransmit
                        # Update the ssthresh and cwnd
                        self.ssthresh = max(len(segments_in_flight) // 2, 2)
                        self.cwnd = self.ssthresh + 3

                        # Resend the first unacknowledged segment
                        unacked_seq, unacked_segment = segments_in_flight[0]
                        self._send_one(PSH_ACK, unacked_segment)

                        # Reset the duplicate ACK counter
                        dup_ack_counter = 0

            else:
                print("Unexpected packet received. Waiting for ACK...")



    # Recv
    def check_incomingPKT(self, packet):
        # Extract the IP and TCP headers from the packet
        ip_datagram, tcp_header, tcp_payload = self.unpack_ip_packet(packet)
        tcp_datagram = self.unpack_tcp_packet(packet)
        if ip_datagram.src_address != self._destIpAddr or ip_datagram.dest_address != self._srcIpAddr:
            # print("Invalid ip address")
            return False
        if tcp_datagram.src_port != self._destPort or tcp_datagram.dest_port != self._srcPort:
            # print("Invalid port")
            return False
        # All checks passed, return True
        if not self.verify_ipv4_checksum(packet) or not self.verify_tcp_checksum(self._destIpAddr, self._srcIpAddr, tcp_header, tcp_payload, tcp_datagram.checksum):
            return False
        return True

    def _receive_one(self, size=20480, timeout=60):
        cur_time = time.time()
        while time.time() - cur_time <= timeout:
            received_pkt = self.recv_socket.recv(size)
            # print(received_pkt.hex())
            if len(received_pkt) == 0:
                continue
            if self.check_incomingPKT(received_pkt):
                ip_datagram = self.unpack_ip_packet(received_pkt)
                tcp_datagram = self.unpack_tcp_packet(received_pkt)
                return tcp_datagram
        return None

    def receive_all1(self):
        received_data = []

        while True:
            # Receive a packet
            tcp_datagram = self._receive_one()

            # If no packet is received, continue waiting
            if tcp_datagram is None:
                continue

            # Check if the received packet is an ACK with payload
            if tcp_datagram.flags & PSH_ACK and not tcp_datagram.flags & FIN and tcp_datagram.ack_seq == self._seq:
                # Check the order of the packet
                if tcp_datagram.seq == self._ack_seq:
                    # Packet is in order, update the ack_seq
                    self._ack_seq += len(tcp_datagram.payload)

                    # Send ACK to the server
                    self._send_one(ACK)

                    # Append the payload to the received_data list
                    received_data.append(tcp_datagram.payload)

                    # Check if the received packet has the FIN flag set
                    if tcp_datagram.flags & FIN:
                        # Send ACK for the FIN flag
                        self._ack_seq += 1
                        self._send_one(ACK)
                        break
                else:
                    # Out of order packet received
                    print("Out of order packet received. Sending ACK with the expected sequence number...")
                    self._send_one(ACK)

            elif tcp_datagram.flags & FIN or (tcp_datagram.flags & (FIN | PSH | ACK)) == (FIN | PSH | ACK):
                print('finish')
                self._ack_seq += 1
                self._send_one(ACK, "")
                break
            else:
                print("Unexpected packet received. Waiting for data...")
            total_payload = b''.join(received_data)

            # print(f'current lenght of recv {len(total_payload) / 1024 / 1024}')

        total_payload = b''.join(received_data)
        header, _, body = total_payload.partition(b'\r\n\r\n')

        return body



    def receive_all2(self, buffer_limit = 65535):
        buffer = {}
        buffer_size = 0

        start_seq = self._ack_seq
        
        data_is_complete_seq = 0x100000000 + 1

        # Initialize the duplicate ACK counter
        dup_ack_counter = 0
        receive_fin = False

        while not receive_fin or data_is_complete_seq != self._ack_seq:
            tcp_datagram = self._receive_one()

            if tcp_datagram is None:
                continue

            print(tcp_datagram.flags)

            if tcp_datagram.ack_seq != self._seq:
                continue

            if tcp_datagram.flags & FIN != 0:
                print("FIN received")
                payload_len = len(tcp_datagram.payload)
                if payload_len != 0:
                    buffer[tcp_datagram.seq] = tcp_datagram.payload 
                buffer_size += payload_len
                # Reset the duplicate ACK counter
                receive_fin = True
                data_is_complete_seq = tcp_datagram.seq + payload_len
                print(f"seq: {tcp_datagram.seq}")
                print(f"FUNC FIN: com_seq: {data_is_complete_seq}, my_ack: {self._ack_seq}")

            # Duplicate packet received
            elif tcp_datagram.seq < self._ack_seq or self._ack_seq in buffer:  
                print('duplicate')
                dup_ack_counter += 1
                if dup_ack_counter >= 3:  # Send duplicate ACK for fast retransmit
                    self._send_one(ACK, "")
                    # Reset the duplicate ACK counter
                    dup_ack_counter = 0
                # Process packets in the correct order from the priority queue

            elif self._ack_seq <= tcp_datagram.seq <= self._ack_seq + buffer_limit:
                payload_len = len(tcp_datagram.payload)
                if payload_len != 0:
                    buffer[tcp_datagram.seq] = tcp_datagram.payload 
                buffer_size += payload_len
                # Reset the duplicate ACK counter
                dup_ack_counter = 0
                
            while self._ack_seq in buffer and self._ack_seq < data_is_complete_seq:
                payload = buffer[self._ack_seq]
                payload_len = len(payload)
                buffer_size -= payload_len
                self._ack_seq += payload_len
                self._ack_seq %= 0x100000000
                self.rwnd = max(1, buffer_limit - buffer_size)
                self._send_one(ACK, "") 
                print("loop mark1")

            print(f"com_seq: {data_is_complete_seq}, my_ack: {self._ack_seq}")               
            
            total_payload = b''.join(received_data)

            print(f'Loop mark2: current lenght of recv {self._ack_seq / 1024 / 1024}')

        # Send ACK respond to FIN
        self._ack_seq += 1
        self._send_one(FIN_ACK, "")

        while start_seq in buffer:
            received_data.append(buffer[start_seq])
            start_seq += len(buffer[start_seq])

        total_payload = b''.join(received_data)
        header, _, body = total_payload.partition(b'\r\n\r\n')

        return body

    # def unpack_ip_packet(self, packet):
    #     IpHeader = namedtuple('IpHeader', ['version', 'header_length', 'ttl', 'protocol', 'src_address', 'dest_address'])
    #     ip_header = unpack('!BBHHHBBH4s4s', packet[:20])
    #     version = ip_header[0] >> 4
    #     header_length = (ip_header[0] & 0xF) * 4
    #     ttl = ip_header[5]
    #     protocol = ip_header[6]
    #     src_address = socket.inet_ntoa(ip_header[8])
    #     dest_address = socket.inet_ntoa(ip_header[9])
    #     return IpHeader(version, header_length, ttl, protocol, src_address, dest_address)

    def unpack_ip_packet(self, packet):
        IpHeader = namedtuple('IpHeader', ['version', 'header_length', 'ttl', 'protocol', 'src_address', 'dest_address'])
        ip_header = unpack('!BBHHHBBH4s4s', packet[:20])
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_address = socket.inet_ntoa(ip_header[8])
        dest_address = socket.inet_ntoa(ip_header[9])

        ip_header_info = IpHeader(version, header_length, ttl, protocol, src_address, dest_address)

        # Check if the packet is TCP
        if protocol != socket.IPPROTO_TCP:
            raise ValueError("The packet is not a TCP packet")

        # Parse TCP header
        tcp_header_len = ((packet[header_length + 12] >> 4) & 0x0F) * 4
        tcp_header = packet[header_length:header_length + tcp_header_len]

        # Extract the TCP payload
        total_length = int.from_bytes(packet[2:4], byteorder='big')
        tcp_payload = packet[header_length + tcp_header_len:total_length]

        return ip_header_info, tcp_header, tcp_payload


    def unpack_tcp_packet(self, packet):
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
        return TcpHeader(src_port, dest_port, sequence_number, acknowledgement_number, header_length, flags, window_size, checksum, urgent_pointer, payload, adwind)

    def handshake(self):
        # send self.seq = 0
        self._send_one(SYN, "")
        # self.seq += 1
        self._seq += 1
        # Expected server,seq = random server.ack = self.seq
        tcp_datagram = self._receive_one()
        if tcp_datagram != None and tcp_datagram.ack_seq == self._seq and tcp_datagram.flags == SYN_ACK:
            # send sefl.seq, self.ack = server.seq + 1
            self._ack_seq = tcp_datagram.seq + 1
            self._send_one(ACK, "")
            print("Connected")
            return True
        print("Receive time expired")
        return False

    def close(self):
        # Send a FIN packet to initiate the connection teardown process
        self._send_one(FIN, "")
        # Increment the sequence number after sending the FIN packet
        self._seq += 1

        # Wait for an ACK packet from the server
        tcp_datagram = self._receive_one()
        if tcp_datagram is not None and tcp_datagram.ack_seq == self._seq and tcp_datagram.flags == ACK:
            # Received ACK for our FIN packet, now wait for the server's FIN packet
            tcp_datagram = self._receive_one()
            if tcp_datagram is not None and (tcp_datagram.flags & FIN) == FIN:
                # Received FIN packet from the server, update the acknowledgment number
                self._ack_seq = tcp_datagram.seq + 1
                # Send the final ACK packet to complete the four-way teardown process
                self._send_one(ACK, "")
                print("Connection closed")
                return True
        print("Error closing connection")
        return False

    def verify_tcp_checksum(self, src_ip, dest_ip, tcp_header, tcp_payload, tcp_checksum):
        def accumulate(accumulator, chunk):
            return accumulator + (chunk >> 8) + (chunk & 0xff)

        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        # Convert IP addresses to integers
        src_ip = int.from_bytes(socket.inet_aton(src_ip), byteorder='big')
        dest_ip = int.from_bytes(socket.inet_aton(dest_ip), byteorder='big')

        # Create pseudo header
        pseudo_header = pack('!4s4sBBH', src_ip.to_bytes(4, byteorder='big'), dest_ip.to_bytes(4, byteorder='big'), 0, socket.IPPROTO_TCP, len(tcp_header) + len(tcp_payload))

        # Pad TCP payload if necessary
        if len(tcp_payload) % 2 == 1:
            tcp_payload += b'\x00'

        # Concatenate pseudo header, TCP header, and TCP payload
        data = pseudo_header + tcp_header + tcp_payload

        # Group the data into 16-bit chunks
        data_chunks = [int.from_bytes(data[i:i + 2], byteorder='big') for i in range(0, len(data), 2)]

        # Calculate the checksum
        total = reduce(carry_around_add, map(accumulate, data_chunks))
        return ~total & 0xffff == tcp_checksum


   
    def verify_ipv4_checksum(self, byte_packet):
        header = byte_packet[:20]

        if len(header) < 20:
            print("Invalid IPv4 header length")
            return False

        version = header[0] >> 4
        if version != 4:
            print("Invalid IP version")
            return False

        ihl = header[0] & 0x0F
        if ihl < 5:
            print("Invalid IPv4 header length field")
            return False

        original_checksum = int.from_bytes(header[10:12], byteorder='big')
        print("Original IP checksum:", original_checksum)

        header = header[:10] + b'\x00\x00' + header[12:]

        values = unpack('!HHHHHHHHHH', header)
        checksum = sum(values)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        calculated_checksum = ~checksum & 0xFFFF

        print("Calculated IP checksum:", calculated_checksum)

        return original_checksum == calculated_checksum
        
