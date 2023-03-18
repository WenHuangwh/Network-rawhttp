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

    def __init__(self, src_ipAddr, dest_ipAddr, src_port, dest_port):
        try:
            # Creates two raw sockets for sending and receiving packets.
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
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
            self.maxcwnd = 1000
            self.cwnd = 1
            self.ssthresh = self.maxcwnd / 2
            self.rwnd = 65535
            # Sets the initial TCP advertised window size to 20480 bytes.
            self.tcp_adwind = socket.htons (self.rwnd)
            # This is ipv4 so Maximum Segment Size is 1460 bytes.
            # Must be an even number
            self.mss = 2
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


    def send(self, data):
        adwnd = 65535
        segments = [data[i:i+self.mss] for i in range(0, len(data), self.mss)]
        buffer = {}
        # Use sequence number as key for buffer
        buffer_key = self._seq

        # Create a buffer of the data segments with their sequence numbers
        for data in segments:
            if len(data) % 2 == 1:
                data += " "
            buffer[buffer_key] = data
            buffer_key += len(data)
        
        # Keep sending data until the buffer is empty
        while self._seq < buffer_key:
            print("while loop")
            window_size = min(self.cwnd, adwnd // self.mss)
            
            # Send packets within the window size
            for i in range(window_size):
                if self._seq not in buffer:
                    packet_number_to_send = i
                    break
                data = buffer[self._seq]
                self._send_one(flags=PSH_ACK, data=data)
                self._seq += len(data)

            # Receive ACKs for the sent packets
            ack_seq_set = set()
            slow_flag = False
            cur_ack_seq = -1
            for i in range(window_size):
                tcp_datagram = self._receive_one(timeout=5)

                # if not tcp_datagram:
                #     slow_flag = True
                #     break

                # # If ACK is received, update adwnd and largest_ack_seq
                # elif tcp_datagram.flags & ACK == ACK:
                #     adwnd = min(65535, tcp_datagram.adwind)
                #     if tcp_datagram.ack_seq in ack_seq_set:
                #         slow_flag = True
                #     else:
                #         cur_ack_seq = max(cur_ack_seq, tcp_datagram.ack_seq)
                
                # # If FIN is received, acknowledge and close the connection
                # elif tcp_datagram.flags & FIN == FIN:
                #     # Acknowledge the received FIN packet
                #     self._ack_seq += 1
                #     self._send_one(flags=ACK, data="")
                #     # Close the connection and break out of the loop
                #     connection_closed = True
                #     break
            

            # self.seq = cur_ack_seq
            self.update_congestion_control(slow_flag)
        
        print("finishi send")



    def update_congestion_control(self, slow_flag):
        if not slow_flag:
            if self.cwnd * 2 <= self.maxcwnd:
                self.cwnd *= 2
            elif self.cwnd < self.maxcwnd:
                self.cwnd += 1
        else:
            self.cwnd = 1


    # Recv
    def check_incomingPKT(self, packet):
        # Extract the IP and TCP headers from the packet
        ip_datagram = self.unpack_ip_packet(packet)
        tcp_datagram = self.unpack_tcp_packet(packet)
        if ip_datagram.src_address != self._destIpAddr or ip_datagram.dest_address != self._srcIpAddr:
            # print("Invalid ip address")
            return False
        if tcp_datagram.src_port != self._destPort or tcp_datagram.dest_port != self._srcPort:
            # print("Invalid port")
            return False
        # All checks passed, return True
        # tcp_header_with_payload = packet[20:]
        # if not self.verify_ipv4_checksum(packet) or not self.verify_tcp_checksum(tcp_header_with_payload, len(tcp_header_with_payload), tcp_datagram.checksum):
        #     return False
        return True

    def _receive_one(self, timeout=60, size=65535):
        try:
            self.recv_socket.settimeout(timeout)
            received_pkt = self.recv_socket.recv(size)
            if len(received_pkt) == 0:
                return None
            if self.check_incomingPKT(received_pkt):
                ip_datagram = self.unpack_ip_packet(received_pkt)
                tcp_datagram = self.unpack_tcp_packet(received_pkt)
                return tcp_datagram
        except socket.timeout:
            return None

    def receive_all(self):
        buffer = None
        start_seq = self._ack_seq
        buffer = self._receive_all()

        received_data = []
        while start_seq in buffer:
            received_data.append(buffer[start_seq])
            start_seq += len(buffer[start_seq])

        total_payload = b''.join(received_data)
        header, _, body = total_payload.partition(b'\r\n\r\n')

        return header, body
        
    def _receive_all(self, buffer_limit = 65535):
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
                self.rwnd = max(1, buffer_limit - buffer_size)
                self._send_one(ACK, "") 

        # Send ACK respond to FIN
        self._ack_seq += 1
        self._send_one(ACK, "")
        self._send_one(FIN_ACK, "")
        self._receive_one()

        return buffer

    def unpack_ip_packet(self, packet):
        IpHeader = namedtuple('IpHeader', ['version', 'header_length', 'ttl', 'protocol', 'src_address', 'dest_address'])
        ip_header = unpack('!BBHHHBBH4s4s', packet[:20])
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_address = socket.inet_ntoa(ip_header[8])
        dest_address = socket.inet_ntoa(ip_header[9])
        return IpHeader(version, header_length, ttl, protocol, src_address, dest_address)

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
        tcp_datagram = self._receive_one(60)
        if tcp_datagram != None and tcp_datagram.ack_seq == self._seq and tcp_datagram.flags == SYN_ACK:
            # send sefl.seq, self.ack = server.seq + 1
            self._ack_seq = tcp_datagram.seq + 1
            self._send_one(ACK, "")
            print("Connected")
            return True
        print("Connect failed")
        return False

    def close(self):
        # Send FIN packet to the server
        self._send_one(FIN, "")

        # Wait for FIN_ACK packet,
        start_time = time.time() 
        tcp_datagram = self._receive_one()

        if tcp_datagram != None and tcp_datagram.flags & FIN_ACK:
            # Server acknowledged the FIN_ACK, break the loop
            self._send_one(ACK, "")
            
        self.send_socket.close()
        self.recv_socket.close()



    def verify_tcp_checksum(self, addr, length, tcp_checksum):
        nleft = length
        total_sum = 0
        index = 0

        while nleft > 1:
            total_sum += int.from_bytes(addr[index:index+2], byteorder='big')
            index += 2
            nleft -= 2

        if nleft == 1:
            answer = int.from_bytes(addr[index:index+1], byteorder='big')
            total_sum += answer

        total_sum = (total_sum >> 16) + (total_sum & 0xFFFF)
        total_sum += (total_sum >> 16)
        answer = ~total_sum & 0xFFFF
        if answer == tcp_checksum:
            print("Right TCP")
        else:
            print(f"Header: {tcp_checksum}, Cal: {answer}")
        return answer == tcp_checksum


   
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
        
