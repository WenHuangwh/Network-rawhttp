



    def verify_tcp_checksum(self, bytes_packet):
        ip_header_bytes = bytes_packet[:20]
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_bytes)
        protocol = ip_header[6]

        if protocol != 6:
            print("Not a TCP packet.")
            return False

        ip_header_length = (ip_header[0] & 0x0F) * 4
        tcp_header_length = ((bytes_packet[ip_header_length + 12] >> 4) & 0xF) * 4
        tcp_header_bytes = bytes_packet[ip_header_length:ip_header_length + tcp_header_length]
        tcp_data = bytes_packet[ip_header_length + tcp_header_length:]

        src_ip, dst_ip = ip_header[8], ip_header[9]
        tcp_length = len(tcp_header_bytes) + len(tcp_data)

        pseudo_header = src_ip + dst_ip + struct.pack('!BBH', 0, protocol, tcp_length)

    def calculate_checksum(data):
            checksum = 0
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    word = (data[i] << 8) + data[i + 1]
                else:
                    word = (data[i] << 8)
                checksum += word
            checksum = (checksum >> 16) + (checksum & 0xFFFF)
            checksum = ~(checksum + (checksum >> 16)) & 0xFFFF
            return checksum

        if len(tcp_data) % 2 != 0:
            tcp_data += b'\x00'

        checksum_data = pseudo_header + tcp_header_bytes[:16] + tcp_header_bytes[18:] + tcp_data
        print("Test the new calculation method, TCP checksum: ", self.checksum(checksum_data))

        calculated_checksum = calculate_checksum(checksum_data)

        original_checksum = (tcp_header_bytes[16] << 8) + tcp_header_bytes[17]
        is_valid = (calculated_checksum == original_checksum)
        print(f"Original TCP checksum: {original_checksum}")
        print(f"Calculated TCP checksum: {calculated_checksum}")

        return is_valid

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
        header = header[:10] + b'\x00\x00' + header[12:]
        print("Test the new calculation method, IP checksum: ", self.checksum(header))

        values = unpack('!HHHHHHHHHH', header)
        checksum = sum(values)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        calculated_checksum = ~checksum & 0xFFFF
        
        print(f"Original IP checksum: {original_checksum}")
        print(f"Calculated IP checksum: {calculated_checksum}")

        return original_checksum == calculated_checksum