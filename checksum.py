import socket, sys, time
import os
from urllib.parse import urlparse
from struct import *
from random import randint
import time
from collections import namedtuple
from functools import reduce
import array

class RawSocket:

    def __init__(self):
        return

    def verify_ipv4_checksum(self, byte_packet):

        ip_header = byte_packet[:20]
        checksum_in_header = (ip_header[10] << 8) + ip_header[11]
        ip_header_with_zero_checksum = ip_header[:10] + b'\x00\x00' + ip_header[12:]
        calculated_checksum = self.checksum(ip_header_with_zero_checksum)
        
        checksum_in_header == calculated_checksum
        print("IP: ")
        print(self.checksum(ip_header))
        print(self.checksum1(ip_header))
        print(self.checksum2(ip_header))
        print(checksum_in_header)
        return 


    def verify_tcp_checksum(self, bytes_packet):

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

        tcp_packet = bytes_packet[20:]
        source_address = ip_header[12:16]
        dest_address = ip_header[16:20]
        pseudo_header = pack('!4s4sBBH',source_address, dest_address, 0, socket.IPPROTO_TCP, len(tcp_packet))

        ip_header_bytes = bytes_packet[:20]
        ip_header = unpack('!BBHHHBBH4s4s', ip_header_bytes)
        protocol = ip_header[6]

        if protocol != 6:
            print("Not a TCP packet.")
            return False

        ip_header_length = (ip_header[0] & 0x0F) * 4
        tcp_header_length = ((bytes_packet[ip_header_length + 12] >> 4) & 0xF) * 4
        tcp_header_bytes = bytes_packet[ip_header_length:ip_header_length + tcp_header_length]
        original_checksum = (tcp_header_bytes[16] << 8) + tcp_header_bytes[17]

        # return self.calculate_checksum(pseudo_header + tcp_packet) == 0

        # Calculate the checksum using the checksum function and compare it to the received checksum
        print("TCP: ")
        print(self.checksum(psh))
        print(self.checksum1(psh))
        print(self.checksum2(psh))
        print(original_checksum)
        return 
            
    def checksum(self, msg):
        if len(msg) % 2 != 0:
            packet += b'\0'
        s = 0  # Initialize the accumulator

        # Loop through the message, taking 2 characters (bytes) at a time
        for i in range(0, len(msg), 2):
            w = (msg[i]) + ((msg[i + 1]) << 8)  # Combine two consecutive bytes into a 16-bit word
            s = s + w  # Add the 16-bit word to the accumulator

        print(f"c1: {s}")

        # Handle carry-over by adding the most significant 16 bits to the least significant 16 bits
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)

        # Calculate the one's complement and mask the result to a 4-byte short (16 bits)
        s = ~s & 0xffff

        return s  # Return the calculated checksum

    def checksum1(self, packet):
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))

        print(f"c2: {res}")

        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

    def checksum2(self, data):
        if len(data) % 2 != 0:
            tcp_data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                word = (data[i] << 8) + data[i + 1]
            else:
                word = (data[i] << 8)
            checksum += word

        print(f"c3: {checksum}")

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~(checksum + (checksum >> 16)) & 0xFFFF

        return checksum

    
    def ip_header(self):

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


    def unpack_ip_packet(self, packet):

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


def main():
    rawSocket = RawSocket()
    bytes_packet = b'E\x00\x00,\xff\xa6\x00\x00\x80\x06d\x93\xcc,\xc0<\xc0\xa8\x89\x80\x00P\xe6\xf3\xceK\x8e.Nm\x0ef`\x12\xfa\xf0&\x02\x00\x00\x02\x04\x05\xb4'
    rawSocket.verify_ipv4_checksum(bytes_packet)
    rawSocket.verify_tcp_checksum(bytes_packet)

main()