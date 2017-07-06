#!/usr/bin/env python2.7
"""
    Simple packet sniffer

    @author: Justin Angra
    @created: Jan 4, 2016
    
    last modified: Jan 4, 2016
    
"""

import socket

def main():
    host = socket.gethostbyname(socket.gethostname()) # public network interface
    
    # create raw socket and bind to public interface
    tcp_sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    tcp_sniffer.bind((host, 0))
    
    # set socket to only receives datagrams with IP headers
    tcp_sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
    
    # listen to network 
    while True:
        try:
            print tcp_sniffer.recvfrom(65565)    
        except socket.error:
            pass
    
    # close socket
    tcp_sniffer.close()

if __name__ == '__main__':
    main()