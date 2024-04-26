import sys
import socket
import random

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import * 

from E2EProtection import E2EProtection
from RAPpacket import *
import os.path


def build_LAA():
    # Build a LAA
    print("Building LAA...")
    laa = LAA(streamId=0xFF00FFAAEEAA, vid=333, listenerAttachStatus=0)
    rapdu1 = RAPDU(type=RAPDU.type.s2i['LAA'], data=laa)
    rapdu1.set_protection()
    records1 = [LRP_Record(recordNumber=7, data=rapdu1, checksum=0)]
    data = raw(records1[0].data)
    records1[0].checksum = fletcher16_checksum(data)
    lrp1 = LRPDU(type=LRPDU.type.s2i['typeRecordLRPDU'], data=records1)
    #lrp1.show2()
    return lrp1


def build_TAA():
    # Build TAA
    print("Building TAA...")
    mTspec = MsrpTspec(interval=64, maximumFramesPerInterval=1, maximumFrameSize=128)
    dfp = DataFrameParameters(destinationMacAddress=0xFEEDDEADBEEF, priority=7,vid= 500)
    taa = TAA(streamId=0x000000000000, streamRank=0, accuMaxLatency=0, accuMinLatency=1024, dataFrameParameters=dfp, msrpTspec=mTspec)

    rapdu = RAPDU(type=RAPDU.type.s2i['TAA'], data=taa)
    rapdu.set_protection()

    records = [LRP_Record(recordNumber=5, data=rapdu)]
    data = raw(records[0].data)
    records[0].checksum = fletcher16_checksum(data)
    lrp = LRPDU(type=LRPDU.type.s2i['typeRecordLRPDU'], data=records)
    #lrp.show2()
    return lrp


class Send:
    @staticmethod
    def get_if():
        ifs=get_if_list()
        iface=None # "h1-eth0"
        for i in get_if_list():
            if "veth2" in i:
                iface=i
                break;
        if not iface:
            print("Not found veth2")
            exit(1)
        return iface

    @staticmethod
    def main(to):

        addr = socket.gethostbyname(to)

        iface = Send.get_if()

        rap = build_TAA()

        #print "sending on interface %s to %s" % (iface, str(addr))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='2e:ae:4b:c3:3f:3a')
        pkt = pkt / ECP(subtype=6) / rap
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
        print("Send ", len(bytes(pkt)), "bytes")


Send.main("192.168.178.5")
