import socket
from enum import IntEnum
from random import randrange


class Encoder:
    @staticmethod
    def int(value: int, length: int = 1) -> bytes:
        return value.to_bytes(length, 'big')

    @staticmethod
    def hex(value, length: int = 4) -> bytes:
        #temp = bytes.fromhex(str(value)[2:])
        return value.to_bytes(length, 'big')

    @staticmethod
    def ip(value: str, length: int = 4) -> bytes:
        return socket.inet_aton(value)

    @staticmethod
    def str(value: str, length: int) -> bytes:
        temp = str.encode(value)
        return temp + (length - len(temp)) * b'\x00'

    @staticmethod
    def mac(value: str, length: int = 6) -> bytes:
        result = bytes.fromhex(value.replace(':', '').lower())
        return result + (length - result.__len__()) * b'\x00'


class Decoder:
    @staticmethod
    def int(value: bytes) -> int:
        return int.from_bytes(value, byteorder='big', signed=False)

    @staticmethod
    def hex(value: bytes) -> int:
        return int.from_bytes(value, byteorder='big', signed=False)

    @staticmethod
    def ip(value: bytes) -> str:
        int_array = [int(x) for x in value]
        ip = '.'.join(str(x) for x in int_array)
        return str(ip)

    @staticmethod
    def str(value: bytes) -> str:
        result = value.decode("utf-8")
        return result.replace('\0', '')

    @staticmethod
    def mac(value: bytes) -> str:
        int_array = [int(x) for x in value]
        mac = ':'.join("{:0>2s}".format(hex(x)[2:]) for x in int_array)
        return mac


class DHCP_Packet_Type(IntEnum):
    NONE = 0
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQEUST = 3
    DHCP_DECLINE = 4
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8


MAGIC_COOKIE = b'\x63\x82\x53\x63'
DHCP_Packet_Fields = [
    {'id': 'op', 'name': 'message_type', 'length': 1, 'type': 'int'},
    {'id': 'htype', 'name': 'hardware_type', 'length': 1, 'type': 'int'},
    {'id': 'hlen', 'name': 'hardware_address_length', 'length': 1, 'type': 'int'},
    {'id': 'hops', 'name': 'hops', 'length': 1, 'type': 'int'},
    {'id': 'xid', 'name': 'transaction_id', 'length': 4, 'type': 'hex'},
    {'id': 'secs', 'name': 'seconds_elapsed', 'length': 2, 'type': 'int'},
    {'id': 'flags', 'name': 'boot_flags', 'length': 2, 'type': 'hex'},
    {'id': 'ciaddr', 'name': 'client_ip_address', 'length': 4, 'type': 'ip'},
    {'id': 'yiaddr', 'name': 'your_ip_address', 'length': 4, 'type': 'ip'},
    {'id': 'siaddr', 'name': 'server_ip_address', 'length': 4, 'type': 'ip'},
    {'id': 'giaddr', 'name': 'gateway_ip_address', 'length': 4, 'type': 'ip'},
    {'id': 'chaddr', 'name': 'client_hardware_address', 'length': 16, 'type': 'mac'},
    {'id': 'sname', 'name': 'server_name', 'length': 64, 'type': 'str'},
    {'id': 'filename', 'name': 'boot_filename', 'length': 128, 'type': 'str'},
    {'id': 'options', 'name': 'options', 'length': 4, 'type': 'hex'},
]


class DHCP_PACKET:
    def __init__(self, data):
        self.message_type = DHCP_Packet_Type(Decoder.int(data[0:1])) if data else DHCP_Packet_Type(0)
        self.hardware_type = Decoder.int(data[1:2]) if data else 1
        self.hardware_address_length = Decoder.int(data[2:3]) if data else 6
        self.hops = Decoder.int(data[3:4]) if data else 0
        self.transaction_id = Decoder.hex(data[4:8]) if data else randrange(0x1_00_00_00_00)    #generate transaction random number
        self.seconds_elapsed = Decoder.int(data[8:10]) if data else 0
        self.boot_flags = Decoder.hex(data[10:12]) if data else 0x0
        self.client_ip_address = Decoder.ip(data[12:16]) if data else '0.0.0.0'     #'1.2.3.4'
        self.your_ip_address = Decoder.ip(data[16:20]) if data else '0.0.0.0'       #'5.6.7.8'
        self.server_ip_address = Decoder.ip(data[20:24]) if data else '0.0.0.0'     #'9.10.11.12'
        self.gateway_ip_address = Decoder.ip(data[24:28]) if data else '0.0.0.0'    #'1.2.3.4'
        self.client_hardware_address = Decoder.mac(data[28:34]) if data else '12:34:45:ab:cd:ef'
        self.server_name = Decoder.str(data[44:108]) if data else ''
        self.boot_filename = Decoder.str(data[108:236]) if data else ''
        self.options = Decoder.int(data[236:240]) if data else int.from_bytes(MAGIC_COOKIE, byteorder='big')

    def encode(self):
        data = b''
        for option in DHCP_Packet_Fields:
            value = getattr(self, option['name'])
            length = option['length']
            function = getattr(Encoder, option['type'])
            data += function(value, length)
        return data

    def __str__(self):
        string = ""
        string += "------Packet Info-------\n"
        string += "Message_type : {}\n".format(self.message_type.name)
        string += "Hardware Type : {}\n".format(self.hardware_type)
        string += "Hardware Address Length : 0x{}\n".format(self.hardware_address_length)
        string += "Hops : {}\n".format(self.hops)
        string += "Transaction Number : {}\n".format(hex(self.transaction_id))
        string += "Seconds Elapsed : {}\n".format(self.seconds_elapsed)
        string += "Boot Flags : {}\n".format(self.boot_flags)
        string += "Client Ip Address : {}\n".format(self.client_ip_address)
        string += "Your Ip Address : {}\n".format(self.your_ip_address)
        string += "Server Ip Address : {}\n".format(self.server_ip_address)
        string += "Gateway Ip Address : {}\n".format(self.gateway_ip_address)
        string += "Client Hardware Address : {}\n".format(self.client_hardware_address)
        string += "Server Name : {}\n".format(self.server_name)
        string += "Boot Filename : {}\n".format(self.boot_filename)
        string += "Options : {}\n".format(hex(self.options))
        return string
