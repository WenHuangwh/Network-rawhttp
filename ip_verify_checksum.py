import binascii
import struct
import socket

def verify_ipv4_checksum(byte_packet):
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
    values = struct.unpack('!HHHHHHHHHH', header)
    checksum = sum(values)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF

    print("IP header calculated checksum", checksum)
    # Verify the checksum
    return original_checksum == checksum

def main():
    # The input header needs to be at least 20 bytes long for a valid IPv4 header. 
    hex_packet = "45 00 00 2c 52 f9 00 00 80 06 11 41 cc 2c c0 3c c0 a8 89 80 00 50 f3 2e a3 cd 48 c6 1e 66 19 1c 60 12 fa af 0a ef e0 00 00 02 04 05 b4 00 00"
    byte_packet = bytes.fromhex(hex_packet.replace(' ', ''))
    # print(verify_packet_checksums(byte_packet)) 
    print("IP header verification result",verify_ipv4_checksum(byte_packet))

    hex_test = "450000287e604000360692262d714518c0a80118"
    byte_test = bytes.fromhex(hex_test.replace(' ', ''))
    print("IP header verification result",verify_ipv4_checksum(byte_test))

if __name__ == "__main__":
    main()