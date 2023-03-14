# Network-rawhttp

class RawSocket:

    send func:
    1. _ip_header

    2. _tcp_header

    3. _send_one
        just send

    4. _send_series
        input is part of data
        cut into series of packets
        send all and wait for response
        check response and decide if: success send all; lost packets ...

    5. send
        use a buffer to store original data
        send parts of buffer according to congestion window using _send_series
        _send_series returns start index of next packet

    recv func:
    1. _receive_one: receive only one packet and call _check

    2. receive: receive all. Call _receive_one and _send_one('ACK'); check order; 
        for loop: 1 - window
        sort
        send ('ACK + sequence number')

    3. _check: check ip, port, checksum of ip and tcp

Considerition now: where to update seq and ack_seq

# main:

1. parse url

2. build connection

3. send request

4. receive request

5. save to file 