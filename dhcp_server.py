import logging as log
import socket
import sys

from dhcp_packet import DHCP_PACKET

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)


class DHCP_Server:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.port = 5005
        self.ip = '127.0.0.1'

    def start_server(self):
        log.info("Starting server")
        self.server_socket.bind((self.ip, self.port))

        while True:
            data = self.server_socket.recv(1024)
            dhcp_packet = DHCP_PACKET(data)
            print(dhcp_packet)


