import logging as log
import socket
import sys

from dhcp_packet import DHCP_PACKET, DHCP_Packet_Type

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)


class DHCP_Server:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.port = 5005
        self.ip = '127.0.0.1'
        self.address_pool = {}
        self.set_address_pool(self.ip, 10)

    def _update_ip_splitter(self, ip_1, ip_2, ip_3, ip_4):
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
        print(self.address_pool)

    def _analyze_data(self, data : bytes):
        dhcp_packet = DHCP_PACKET(data)
        print(dhcp_packet)
        if dhcp_packet.message_type == DHCP_Packet_Type.DHCP_DISCOVER:
            log.info("DHCP_DISCOVER received")
            dhcp_packet.message_type = DHCP_Packet_Type.DHCP_OFFER
            available_address = self.getFreeAddress()
            if available_address is not None:
                dhcp_packet.your_ip_address = available_address
            print(dhcp_packet)
            #self.server_socket.send(dhcp_packet.encode(), ('127.0.0.255', self.port))
        elif dhcp_packet.message_type == DHCP_Packet_Type.DHCP_REQEUST:
            log.info("DHCP_DISCOVER received")
            #to be completed
            dhcp_packet.message_type = DHCP_Packet_Type.DHCP_ACK
            dhcp_packet.client_ip_address = dhcp_packet.your_ip_address
            self.address_pool.update({dhcp_packet.client_ip_address: dhcp_packet.client_hardware_address})

            #self.server_socket.send(dhcp_packet.encode(), self.port)


    def start_server(self):
            log.info("Starting server")
            self.server_socket.bind((self.ip, self.port))

            while True:
                data = self.server_socket.recv(1024)
                self._analyze_data(data)

    def getFreeAddress(self):
        print(self.address_pool)
        for ip, mac in self.address_pool.items():
            if mac is None:
                return ip
            return None


