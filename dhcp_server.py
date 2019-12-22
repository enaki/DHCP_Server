import logging as log
import socket
import sys

from dhcp_packet import DHCP_PACKET, DHCP_Packet_Type

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)

server_port = 67
client_port = 68
MAX_BYTES = 1024


class DHCP_Server:
    def __init__(self):
        self.ip = '0.0.0.0'
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.dest = ('255.255.255.255', client_port)

        self.address_pool = {}
        self.set_address_pool('10.0.0.1', 10)

    @staticmethod
    def _update_ip_splitter(ip_1, ip_2, ip_3, ip_4):
        ip_4 += 1
        if ip_4 == 255:
            ip_4 = 1
            ip_3 += 1
        if ip_3 == 255:
            ip_3 = 1
            ip_2 += 1
        if ip_2 == 255:
            ip_2 = 1
            ip_1 += 1
        if ip_1 == 255:
            ip_1 = 1
        return ip_1, ip_2, ip_3, ip_4

    def set_address_pool(self, starting_ip, number_of_addresses: int):
        ip_1, ip_2, ip_3, ip_4 = [int(s) for s in starting_ip.split('.')]
        if ip_4 == 0 or starting_ip == self.ip:
            ip_1, ip_2, ip_3, ip_4 = self._update_ip_splitter(ip_1, ip_2, ip_3, ip_4)
        for i in range(number_of_addresses):
            self.address_pool.update({"{}.{}.{}.{}".format(ip_1, ip_2, ip_3, ip_4): None})
            ip_1, ip_2, ip_3, ip_4 = self._update_ip_splitter(ip_1, ip_2, ip_3, ip_4)
        #print(self.address_pool)

    def _send_offer(self, dhcp_packet):
        log.info("Sending DHCP_OFFER")
        dhcp_packet.message_type = DHCP_Packet_Type.DHCP_OFFER
        available_address = self.get_free_address()
        if available_address is not None:
            dhcp_packet.your_ip_address = available_address
        message = dhcp_packet.encode()
        self.server_socket.sendto(message, self.dest)

    def _send_acknowledge(self, dhcp_packet):
        log.info("Sending DHCP_ACKNOWLEDGE")
        dhcp_packet.message_type = DHCP_Packet_Type.DHCP_ACK
        dhcp_packet.client_ip_address = dhcp_packet.your_ip_address
        self.address_pool.update({dhcp_packet.client_ip_address: dhcp_packet.client_hardware_address})
        # self.server_socket.send(dhcp_packet.encode(), self.port)
        message = dhcp_packet.encode()
        self.server_socket.sendto(message, self.dest)

    def _send_nacknowledge(self, dhcp_packet):
        log.info("Sending DHCP_NEGATIVE_ACKNOWLEDGE")
        dhcp_packet.message_type = DHCP_Packet_Type.DHCP_NAK
        message = dhcp_packet.encode()
        self.server_socket.sendto(message, self.dest)

    def _analyze_data(self, data: bytes):
        dhcp_packet = DHCP_PACKET(data)
        print(dhcp_packet)
        if dhcp_packet.message_type == DHCP_Packet_Type.DHCP_DISCOVER:
            log.info("DHCP_DISCOVER received")
            self._send_offer(dhcp_packet)
        elif dhcp_packet.message_type == DHCP_Packet_Type.DHCP_REQEUST:
            log.info("DHCP REQUEST received")
            if self.ip_address_is_free(dhcp_packet.your_ip_address):
                self._send_acknowledge(dhcp_packet)
            else:
                self._send_nacknowledge(dhcp_packet)

    def start_server(self):
        log.info("Starting server")
        self.server_socket.bind(('', server_port))

        while True:
            data, address = self.server_socket.recvfrom(MAX_BYTES)
            print(address)
            self._analyze_data(data)

    def get_free_address(self):
        print(self.address_pool)
        for ip, mac in self.address_pool.items():
            if mac is None:
                return ip
            return None

    def ip_address_is_free(self, ip):
        if self.address_pool[ip] is None:
            return True
        return False

