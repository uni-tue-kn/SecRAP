from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import * 

from E2EProtection import E2EProtection

import os.path

# X.509 certificate which containes the public key to verify signatures
public_key= "ec_dsa.crt"    #X.509 certificate
certificate = ""


if not os.path.isfile(public_key):
    print('Public key does not exist.')
else:
    # Open the file and read its content.
    with open(public_key) as f:
        certificate = f.read()
        print('Public key imported.')


# Private key used for creating signatures
key = ""
private_key = 'ec_key.pem'

if not os.path.exists(private_key):
    print('Private key does not exist!')
else:
    with open(private_key, 'rb') as pem_in:
        key = pem_in.read()
        print('Private key imported.')


class ProtectionHdr(Packet):
    name = "ProtectionHdr"
    fields_desc = [ FieldLenField("certificateLength", None, fmt='H', length_of="certificate"),
                    StrLenField("certificate", "", length_from=lambda x:x.certificateLength),
                    FieldLenField("signatureLength", None, fmt='H', length_of="signature"),
                    StrLenField("signature", "", length_from=lambda x:x.signatureLength),
    ]

class DataFrameParameters(Packet):
    name = "DataFrameParameters"
    fields_desc = [ BitField("type", 0x22, 8),
                    BitField("lenght", 0x08, 16),
                    BitField("destinationMacAddress", 0x000000000000, 48),
                    BitField("priority", 0x00000000, 3),
                    BitField("reserved", 0x0, 1),
                    BitField("vid", 0x0, 12)
            ]
    def extract_padding(self, s):
        return '', s

class MsrpTspec(Packet):
    name = "MsrpTspec"
    fields_desc = [ BitField("type", 0x24, 8),
                    BitField("lenght", 0x08, 16),
                    BitField("interval", 0x00000000, 32),
                    BitField("maximumFramesPerInterval", 0x0000, 16),
                    BitField("maximumFrameSize", 0x0000, 16)
            ]
    def extract_padding(self, s):
        return '', s



class TAA(Packet):
    name = "TAA"
    fields_desc = [ BitField("streamId", 0x00000000, 64),
                    BitField("streamRank", 0x00000000, 8),
                    BitField("accuMaxLatency", 0x00000000, 32),
                    BitField("accuMinLatency", 0x00000000, 32),
                    PacketField("dataFrameParameters", None, DataFrameParameters),
                    PacketField("msrpTspec", None, MsrpTspec)
                    
            ]
    def extract_padding(self, s):
        return '', s


class LAA(Packet):
    name = "LAA"
    fields_desc = [ BitField("streamId", 0x00000000, 64), # proteced
                    BitField("vid", 0b000000000000, 12),   # protected
                    BitField("listenerAttachStatus", 0b0000, 4),
    ]
    def extract_padding(self, s):
        return '', s


class RAPDU(Packet):
    name = "RAPDU"
    fields_desc = [ ByteEnumField("type", 0x00, {0x01 : "TAA", 0x02 : "LAA"}),  
                    FieldLenField("length", None, fmt='H', length_of="data"),          # 2 Byte
                    MultipleTypeField([
                        (PacketField("data", None, TAA),lambda pkt:pkt.type==0x01),
                        (PacketField("data", None, LAA),lambda pkt:pkt.type==0x02)
                    ],
                    StrField("data", "")),
                    PacketField("protection", None, ProtectionHdr)
                    #StrLenField("data", "", length_from=lambda x:x.length),   
                    #PacketListField("data", None, , length_from=lambda x:x.length),   
    ]
    def extract_padding(self, s):
        return '', s

    def get_constant_data(self):
        result = b''
        
        if self.type == 0x01:
            result = bytes(str(self.data.streamId) + str(self.data.dataFrameParameters) + str(self.data.msrpTspec),"utf8")
        elif self.type == 0x02:
            result = bytes(str(self.data.streamId) + str(self.data.vid),"utf8")
        return result

    def set_protection(self):
        self.protection = ProtectionHdr(certificate=certificate)
        #print("RAW Packet to set: ", raw(self))
        data = self.get_constant_data()
        signature = E2EProtection.generate_signature(key, data)
        self.protection.signature = signature

        return

    def validate_protection(self):
        # Safe signature and signature length
        signature_length = self.protection.signatureLength
        signature = self.protection.signature

        # Prepater packet
        self.protection.signatureLength = None
        self.protection.signature = ""

        data = self.get_constant_data()

        #print("RAW PAcket to validate: ", raw(self))
        #print(signature)
        # Check signature
        result = E2EProtection.verify_signature(self.protection.certificate, signature, data)

        # Restore packet
        self.protection.signatureLength = signature_length
        self.protection.signature = signature
        
        return result


class LRP_Record(Packet):
    name = "LRP_Record"
    fields_desc = [ BitField("recordNumber", 0x00, 32), # 4 Byte   
                    BitField("sequenceNumber", 0x00, 32),
                    BitField("checksum", 0x00, 16),
                    FieldLenField("length", None, fmt='H', length_of="data"),          
                    #StrLenField("data", "", length_from=lambda x:x.length),   
                    PacketField("data", None, RAPDU)#, length_from=lambda x:x.length)
    ]
    def extract_padding(self, s):
        return '', s


class LRPDU(Packet):
    name = "LRPDU"
    fields_desc = [ ByteEnumField("type", 0x00, {0x02 : "typeRecordLRPDU"}),  
                    FieldLenField("length", None, fmt='H', length_of="data"),          
                    BitField("portalNo", 0x00, 64),
                    PacketListField("data", None, LRP_Record, length_from=lambda x:x.length),   
    ]

class ECP(Packet):
    name = "ECP"
    fields_desc = [ BitField("version",1, 4),
                    BitField("operationType", 0b00, 2),
                    BitField("subtype", 0b0000, 10),
                    BitField("sequenceNumber", 0x00, 16)
    ]

class ECPTLS(Packet):
    name = "ECP-TLS"
    fields_desc = [BitField("Signatur", 0x0, 256),
                  BitField("proto", 0, 16),
                  BitField("sequenceNumber", 0x00, 64)]

bind_layers(Ether,ECP,type=0x8940)
bind_layers(ECP, ECPTLS, subtype=0x4)
bind_layers(ECP, IP, subtype=0x5)
bind_layers(ECP, LRPDU, subtype=0x6)
bind_layers(ECPTLS, LRPDU, proto=0x6)
bind_layers(ECPTLS, IP, proto=0x5)
bind_layers(RAPDU, TAA, type=0x1)
bind_layers(RAPDU, LAA, type=0x2)

