import socket, sys, time
import os
from urllib.parse import urlparse
from struct import *
from random import randint
import time
from collections import namedtuple

SYN = 0x02   # 0b00000010
ACK = 0x10   # 0b00010000
SYN_ACK = 0x12   # 0b00010010
FIN = 0x01   # 0b00000001
FIN_ACK = 0x11   # 0b00010001
PSH_ACK = 0x18   # 0b00011000

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
            self._seq = randint(0, (2 << 31) - 1)
            
            # Sets the initial TCP acknowledgement sequence number to 0.
            self._ack_seq = 0

            self.ip_id = 1
            
            # Sets the initial TCP advertised window size to 20480 bytes.
            self.tcp_adwind = socket.htons (5840)
            
            # Congestion control variables.
            # Sets the initial congestion window size to 1.
            self.cwnd = 1
            # Sets the initial slow start flag to True, indicating that the congestion avoidance algorithm
            # is in the slow start phase.
            self.slow_start_flag = True
            # Maximum Segment Size is 512 bytes.
            self.mss = 512
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
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(self._srcIpAddr)
        ip_daddr = socket.inet_aton(self._destIpAddr)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
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
        # Split the data into segments according to the MSS
        segments = [data[i:i+self.mss] for i in range(0, len(data), self.mss)]

        for segment in segments:
            if len(segment) % 2 == 1:
                segment += " "
            # Send the data segment
            self._send_one(PSH_ACK, segment)
            self._seq += len(segment)

            # Wait for the ACK from the server
            while True:
                tcp_datagram = self._receive_one()
                if tcp_datagram is None:
                    continue
                # Check if the received packet is an ACK for the current data segment
                if tcp_datagram.flags == ACK and tcp_datagram.ack_seq == self._seq:
                    # Update the acknowledgement sequence number
                    self._ack_seq = tcp_datagram.seq + len(tcp_datagram.payload)
                    break
                else:
                    print("Unexpected packet received. Waiting for ACK...")


    # Recv
    def check_incomingPKT(self, packet):
        # Extract the IP and TCP headers from the packet
        ip_datagram = self.unpack_ip_header(packet)
        tcp_datagram = self.unpack_tcp_header(packet)
        if ip_datagram.src_address != self._destIpAddr or ip_datagram.dest_address != self._srcIpAddr:
            # print("Invalid ip address")
            return False
        if tcp_datagram.src_port != self._destPort or tcp_datagram.dest_port != self._srcPort:
            # print("Invalid port")
            return False
        # All checks passed, return True
        return True

    def _receive_one(self, size=20480, timeout=60):
        cur_time = time.time()
        while time.time() - cur_time <= timeout:
            received_pkt = self.recv_socket.recv(size)
            # print(received_pkt.hex())
            if len(received_pkt) == 0:
                continue
            if self.check_incomingPKT(received_pkt):
                ip_datagram = self.unpack_ip_header(received_pkt)
                tcp_datagram = self.unpack_tcp_header(received_pkt)
                return tcp_datagram
        return None

    def receive_all(self):
        received_data = []

        while True:
            # Receive a packet
            tcp_datagram = self._receive_one()
            

            # If no packet is received, continue waiting
            if tcp_datagram is None:
                continue

            # Check if the received packet is an ACK with payload
            if tcp_datagram.flags & PSH_ACK and tcp_datagram.ack_seq == self._seq:
                # Update sequence and acknowledgement numbers
                self._seq = tcp_datagram.ack_seq
                self._ack_seq = tcp_datagram.seq + len(tcp_datagram.payload)

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
                print("Unexpected packet received. Waiting for data...")

        # Combine received payloads
        total_payload = b''.join(received_data)

        # Decode payload to a string, assuming UTF-8 encoding
        try:
            payload_string = total_payload.decode('utf-8')
        except UnicodeDecodeError:
            print("Unable to decode payload using UTF-8 encoding.")
            payload_string = None

        return payload_string


    def unpack_ip_header(self, packet):
        IpHeader = namedtuple('IpHeader', ['version', 'header_length', 'ttl', 'protocol', 'src_address', 'dest_address'])
        ip_header = unpack('!BBHHHBBH4s4s', packet[:20])
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_address = socket.inet_ntoa(ip_header[8])
        dest_address = socket.inet_ntoa(ip_header[9])
        return IpHeader(version, header_length, ttl, protocol, src_address, dest_address)

    def unpack_tcp_header(self, packet):
        TcpHeader = namedtuple('TcpHeader', ['src_port', 'dest_port', 'seq', 'ack_seq', 'header_length', 'flags', 'window_size', 'checksum', 'urgent_pointer', 'payload'])
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
        payload = packet[header_length:]
        return TcpHeader(src_port, dest_port, sequence_number, acknowledgement_number, header_length, flags, window_size, checksum, urgent_pointer, payload)


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

