    def checksum(self, msg):
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