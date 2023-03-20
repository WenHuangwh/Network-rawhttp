from struct import pack, unpack
from utils import *


class TCPPacket:
    """
       This class is used to represent a TCP packet.
    """
    def __init__(self, src_ip = '', dest_ip = '', src_port = 0, dest_port = 0,
                 seq_num = 0, ack_num = 0, flags = 0, payload =b'',
                 raw_bytes = b'', mss = DEFAULT_MSS):
        """
        Initialize a TCP packet.

        Parameters
        ----------
        src_ip : str
            Source IP address
        dest_ip : str
            Destination IP address
        src_port : int
            Source port number
        dest_port : int
            Destination port number
        seq_num : int
            Sequence number
        ack_num : int
            Acknowledgement number
        flags : int
            TCP flags
        payload : bytes
            TCP payload bytes
        raw_bytes : bytes
            Raw bytes of the TCP packet
        mss : int
            Maximum segment size
        """
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.offset = DEFAULT_TCP_OFFSET
        self.adv_window = DEFAULT_TCP_ADV_WINDOW
        self.urg_ptr = DEFAULT_TCP_URG_PTR
        self.payload = payload
        self.options = b''
        self.raw_bytes = raw_bytes
        self.checksum = DEFAULT_CHECKSUM
        self.mss = mss

        if raw_bytes:
            self.tcp_unpack()
        else:
            self.tcp_pack()

    def tcp_pack(self):
        """
        Pack the TCP header and payload into raw bytes.
        """
        # Get temp tcp_header
        tcp_header = pack(TCP_HEADER_FORMAT,
                          self.src_port,
                          self.dest_port,
                          self.seq_num,
                          self.ack_num,
                          self.offset << 4,
                          self.flags,
                          self.adv_window,
                          DEFAULT_CHECKSUM,
                          self.urg_ptr)

        # Update the checksum with pseudo header
        self.checksum = self.get_tcp_checksum(tcp_header)

        # Get the final tcp_header
        tcp_header_final = pack(TCP_HEADER_SHORT_FORMAT,
                                self.src_port,
                                self.dest_port,
                                self.seq_num,
                                self.ack_num,
                                self.offset << 4,
                                self.flags,
                                DEFAULT_TCP_ADV_WINDOW) \
                           + pack('H', self.checksum) \
                           + pack('!H', DEFAULT_TCP_URG_PTR)

        self.raw_bytes = tcp_header_final + self.payload

    def tcp_unpack(self):
        """
        Unpack the raw bytes into TCP header and payload.
        """

        # Unpack the tcp header
        # Assume TCP header is 20 bytes
        raw_tcp_header = self.raw_bytes[:20]
        tcp_header = unpack(TCP_HEADER_SHORT_FORMAT, raw_tcp_header[0:16]) \
                    + unpack('H', raw_tcp_header[16:18]) \
                    + unpack('!H', raw_tcp_header[18:20])
        self.src_port = tcp_header[0]
        self.dest_port = tcp_header[1]
        self.seq_num = tcp_header[2]
        self.ack_num = tcp_header[3]
        self.offset = tcp_header[4] >> 4

        if (self.offset > 5):
            self.options = self.raw_bytes[20:self.offset * 4]
            received_mss = unpack('!H', self.options[0:4][2:])[0]
            if received_mss > 0:
                self.mss = received_mss
            # print("Received MSS: ", self.mss)
        self.flags = tcp_header[5]
        self.adv_window = tcp_header[6]
        self.checksum = tcp_header[7]
        self.urg_ptr = tcp_header[8]
        self.payload = self.raw_bytes[self.offset * 4:]

    # Build pseudo ip header and calculate original tcp checksum
    def get_tcp_checksum(self, tcp_header):
        """
        Calculate the TCP checksum.

        Parameters
        ----------
        tcp_header : bytes
            TCP header in bytes
        """
        source_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(self.payload)

        pseudo_header = pack(PSEUDO_HEADER_FORMAT, source_address, dest_address,
                             placeholder, protocol, tcp_length)
        final_pseudo_header = pseudo_header + tcp_header + self.payload

        tcp_check = calculate_checksum(final_pseudo_header)
        return tcp_check

    def validate_tcp_checksum(self, src_ip, dest_ip):
        """
        Validate the TCP checksum.

        Parameters
        ----------
        src_ip : str
            Source IP address
        dest_ip : str
            Destination IP address

        Returns
        -------
        bool
            True if the checksum is valid, False otherwise
        """
        source_address = socket.inet_aton(src_ip)
        dest_address = socket.inet_aton(dest_ip)
        pseudo_header = pack(PSEUDO_HEADER_FORMAT,
                             source_address, dest_address,
                             0, socket.IPPROTO_TCP,
                             len(self.raw_bytes))

        return calculate_checksum(pseudo_header + self.raw_bytes) == 0


    def calculate_checksum(packet):
        """
        Calculate the checksum of a packet in bytes. Referenced from
        https://www.kytta.dev/blog/tcp-packets-from-scratch-in-python-3/
        Parameters
        ----------
        packet: bytes
            Raw bytes of a packet
        Returns
        -------
        int
            Checksum of the packet
        """
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

from struct import pack, unpack
import socket
import array

class TCPPacket:
    # ... (previous code)

    @staticmethod

    def calculate_checksum(self, packet):
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

    def validate_tcp_checksum(self):
        raw_packet = self.raw_bytes
        ip_header_bytes = raw_packet[:20]
        ip_header = unpack('!BBHHHBBH4s4s', ip_header_bytes)
        protocol = ip_header[6]

        if protocol != 6:
            print("Not a TCP packet.")
            return False

        ip_header_length = (ip_header[0] & 0x0F) * 4
        tcp_header_length = ((raw_packet[ip_header_length + 12] >> 4) & 0xF) * 4
        tcp_header_bytes = raw_packet[ip_header_length:ip_header_length + tcp_header_length]
        tcp_data = raw_packet[ip_header_length + tcp_header_length:]

        src_ip, dst_ip = ip_header[8], ip_header[9]
        src_address = socket.inet_aton(src_ip)
        dst_address = socket.inet_aton(dst_ip)

        tcp_length = len(tcp_header_bytes) + len(tcp_data)

        pseudo_header = pack('!4s4sBBH', src_address, dst_address, 0, protocol, tcp_length)
        checksum_data = pseudo_header + tcp_header_bytes[:16] + tcp_header_bytes[18:] + tcp_data
        calculated_checksum = self.calculate_checksum(checksum_data)

        original_checksum = (tcp_header_bytes[16] << 8) + tcp_header_bytes[17]
        is_valid = (calculated_checksum == original_checksum)

        return is_valid

# ...

# Example usage:
packet = TCPPacket(raw_bytes=b'...')  # Your raw packet bytes
is_valid = packet.validate_tcp_checksum()
print(is_valid)






    def calculate_checksum(self, packet):
        """
        Calculate the checksum of a packet in bytes. Referenced from
        https://www.kytta.dev/blog/tcp-packets-from-scratch-in-python-3/
        Parameters
        ----------
        packet: bytes
            Raw bytes of a packet
        Returns
        -------
        int
            Checksum of the packet
        """
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff


    def verify_tcp_checksum(self, packet):
        tcp_packet = packet[20:]
        source_address = socket.inet_aton(self._destIpAddr)
        dest_address = socket.inet_aton(self._srcIpAddr)
        pseudo_header = pack('!4s4sBBH',source_address, dest_address, 0, socket.IPPROTO_TCP, len(tcp_packet))

        return self.calculate_checksum(pseudo_header + tcp_packet) == 0