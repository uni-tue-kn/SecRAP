import sys
import socket
import random

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import * 

from E2EProtection import E2EProtection
from RAPpacket import *


class Receive(object):

    @staticmethod
    def handle_pkt(pkt):
        pkt.show2()
        if "RAPDU" in pkt:
            p = pkt[RAPDU]
            p.validate_protection()
            
    @staticmethod
    def main():
        ifaces = list(filter(lambda i: 'veth1' in i, os.listdir('/sys/class/net/')))
        iface = ifaces[0]
        sys.stdout.flush()
        sniff(iface = iface,
              prn = lambda x: Receive.handle_pkt(x))


Receive.main()




