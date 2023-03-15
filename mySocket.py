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
        tcp_header = self.tcp_header(flags, data, ack_seq)
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
        # if not self.verify_ipv4_checksum(packet) or not self.verify_tcp_checksum(packet):
        #     print("Packet: ")
        #     print(packet.hex())
        #     return False
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

            else:
                print("Unexpected packet received. Waiting for data...")

        # Combine received payloads
        total_payload = b''.join(received_data)     

        # Split the payload to remove the HTTP header
        header, _, body = total_payload.partition(b'\r\n\r\n')

        return body


    



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
        payload = packet[20 + header_length:]
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

    def verify_tcp_checksum(self, byte_packet):
        # Extract the IP header from the packet bytes
        ip_header_length = (byte_packet[0] & 0x0F) * 4
        ip_header = byte_packet[:ip_header_length]

        # Verify the total length of the packet
        total_length = unpack('!H', ip_header[2:4])[0]
        print("total_length",total_length)
        print("len packet", len(byte_packet))
        # if total_length != len(packet):
        #     return False

        # Extract the TCP header from the packet bytes
        tcp_header_offset = ip_header_length
        tcp_header_length = (byte_packet[tcp_header_offset + 12] >> 4) * 4
        tcp_header = byte_packet[tcp_header_offset:tcp_header_offset+tcp_header_length]

        # Extract the original TCP checksum value from the TCP header
        original_checksum = unpack('!H', tcp_header[16:18])[0]
        print("original checksum", original_checksum)

        if original_checksum == 0:
            return True

        # Set the checksum field in the TCP header to zero
        tcp_header = bytearray(tcp_header)
        pack_into('!H', tcp_header, 16, 0)

        # Calculate the checksum over the TCP pseudo-header, TCP header, and TCP data
        pseudo_header = ip_header[12:20] + b'\x00\x06' + pack('!H', total_length - ip_header_length)
        tcp_data_offset = tcp_header_offset + tcp_header_length
        tcp_data = byte_packet[tcp_data_offset:]

        # Pad data with a zero byte if its length is not a multiple of 2
        if len(tcp_data) % 2 != 0:
            tcp_data += b'\x00'

        checksum = 0
        for chunk in [pseudo_header, tcp_header, tcp_data]:
            for i in range(0, len(chunk), 2):
                word = (chunk[i] << 8) + chunk[i+1]
                checksum += word

        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + (checksum >> 16)

        calculated_checksum = ~checksum & 0xffff
        print("calculated checksum", calculated_checksum)
        
        # Verify the checksum
        is_valid = (calculated_checksum == original_checksum)

        # Return the original TCP checksum value and whether the calculated checksum is valid
        return is_valid

    def verify_ipv4_checksum(self, byte_packet):
        """
        Verifies the checksum of an IPv4 header.

        Args:
            header (bytes): The IPv4 header as bytes.
            The input header needs to be at least 20 bytes long for a valid IPv4 header. 

        Returns:
            bool: True if the checksum is valid, False otherwise.
        """
        header = byte_packet[:20]

        if len(header) < 20:
            print("Invalid IPv4 header length")
            return False

        # Calculate the new checksum
        if len(header) % 2 == 1:
            # Append a padding byte to ensure that the header length is even
            header += b'\x00'

        version = header[0] >> 4
        print("ip version", version)
        if version != 4:
            print("Invalid IP version")
            return False

        ihl = header[0] & 0x0F
        print("IPv4 header length field", ihl)
        if ihl < 5:
            print("Invalid IPv4 header length field")
            return False
        
        # Extract the original checksum from the header
        original_checksum = int.from_bytes(header[10:12], byteorder='big')
        print("IP header original checksum", original_checksum)
        
        # Set the checksum field in the header to zero
        header = header[:10] + b'\x00\x00' + header[12:]

        # Calculate the new checksum
        values = unpack('!HHHHHHHHHH', header)
        checksum = sum(values)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = ~checksum & 0xFFFF

        print("IP header calculated checksum", checksum)
        # Verify the checksum
        return original_checksum == checksum