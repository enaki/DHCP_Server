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


class DHCP_Message_Type(IntEnum):
    NONE = 0
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_DECLINE = 4
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8


class DHCP_Opcode(IntEnum):
    NONE = 0
    REQUEST = 1
    REPLY = 2


#   for all DHCP_OPTIONS go to
#   https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
class DHCP_Options(IntEnum):
    OP_PADDING = 0
    OP_SUBNETMASK = 1
    OP_ROUTER = 3
    OP_DNS = 6
    OP_BROADCAST_ADDRESS = 28
    OP_REQUESTED_IP = 50
    OP_LEASE_TIME = 51
    OP_MESSAGE_TYPE = 53
    OP_PARAM_REQ_LIST = 55
    OP_RENEWAL_TIME = 58
    OP_REBINDING_TIME = 59
    OP_CLIENT_ID = 61
    OP_END = 255


MAGIC_COOKIE = b'\x63\x82\x53\x63'
DHCP_Packet_Fields = [
    {'id': 'op', 'name': 'opcode', 'length': 1, 'type': 'int'},
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
    {'id': 'magic_cookie', 'name': 'magic_cookie', 'length': 4, 'type': 'hex'},
]

#these fields will be added to dhcp packet
DHCP_Options_Fields = [
    {'id': DHCP_Options.OP_MESSAGE_TYPE, 'name': 'message_type', 'length': 1, 'type': 'int'},
    {'id': DHCP_Options.OP_SUBNETMASK, 'name': 'subnet_mask', 'length': 1, 'type': 'int'},
    {'id': DHCP_Options.OP_BROADCAST_ADDRESS, 'name': 'broadcast_address', 'length': 4, 'type': 'ip'},
    {'id': DHCP_Options.OP_LEASE_TIME, 'name': 'lease_time', 'length': 4, 'type': 'int'},
    {'id': DHCP_Options.OP_RENEWAL_TIME, 'name': 'renewal_time', 'length': 4, 'type': 'int'},
    {'id': DHCP_Options.OP_REBINDING_TIME, 'name': 'rebinding_time', 'length': 4, 'type': 'int'},
]


class DHCP_PACKET:
    def __init__(self, data, opcode=DHCP_Opcode.NONE, message_type=DHCP_Message_Type.NONE, subnet_mask=None, broadcast_address=None, lease_time=None):
        self.opcode = DHCP_Opcode(Decoder.int(data[0:1])) if data else opcode
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
        self.magic_cookie = Decoder.int(data[236:240]) if data else int.from_bytes(MAGIC_COOKIE, byteorder='big')

        #dhcp options
        self.message_type = message_type
        self.subnet_mask = subnet_mask
        self.broadcast_address = broadcast_address
        self.lease_time = lease_time
        self.renewal_time = lease_time // 2 if self.lease_time is not None else None
        self.rebinding_time = lease_time * 7 // 8 if self.lease_time is not None else None
        if data:
            self.decode_options(data[240:])

    def set_lease_time(self, lease_time):
        self.lease_time = lease_time
        self.renewal_time = lease_time // 2 if self.lease_time is not None else None
        self.rebinding_time = lease_time * 7 // 8 if self.lease_time is not None else None

    def decode_options(self, data_options):
        index = 0
        int_byte_value = 0
        while index < data_options.__len__() and data_options[index] != 255:
            try:
                int_byte_value = data_options[index]
                option = next(item for item in DHCP_Options_Fields if item['id'] == DHCP_Options(int_byte_value))
                length_option = option['length']
                index += 2
                function_for_decoding = getattr(Decoder, option['type'])
                setattr(self, option['name'], function_for_decoding(data_options[index: index+length_option]))
                index += length_option
            except ValueError:
                #Received package from another server
                import logging as log
                log.info("Dhcp option {} is unknown for me".format(int_byte_value))
                break

    def encode(self):
        data = b''
        for option in DHCP_Packet_Fields:
            value = getattr(self, option['name'])
            length = option['length']
            function = getattr(Encoder, option['type'])
            data += function(value, length)
        for option in DHCP_Options_Fields:
            value = getattr(self, option['name'])
            length = option['length']
            if value is not None:
                function = getattr(Encoder, option['type'])
                data += Encoder.int(option['id']) + Encoder.int(length) + function(value, length)
        data += Encoder.int(DHCP_Options.OP_END)
        return data

    def __str__(self):
        string = ""
        string += "------Packet Info-------\n"
        string += "Opcode : {}\n".format(self.opcode.name)
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
        string += "Magic Cookie : {}\n".format(hex(self.magic_cookie))
        string += "--Options\n"
        string += "Message Type : {}\n".format(DHCP_Message_Type(self.message_type).name) if self.message_type != DHCP_Message_Type.NONE else ""
        string += "Broadcast Address : {}\n".format(self.broadcast_address) if self.broadcast_address is not None else ""
        string += "Subnet Mask : /{}\n".format(self.subnet_mask) if self.subnet_mask is not None else ""
        string += "Lease Time : {}\n".format(self.lease_time) if self.lease_time is not None else ""
        string += "Renewal Time : {}\n".format(self.renewal_time) if self.renewal_time is not None else ""
        string += "Rebinding Time : {}\n".format(self.rebinding_time) if self.rebinding_time is not None else ""
        return string
