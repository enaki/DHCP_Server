import select
import socket

from dhcp_packet import DHCP_PACKET, DHCP_Message_Type, DHCP_Opcode
from dhcp_server import log

serverPort = 67
clientPort = 68
MAX_BYTES = 1024

UDP_IP = '0.0.0.0'
UDP_PORT = 68


def client_1():
    dst = ('<broadcast>', serverPort)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, clientPort))

    log.info("Sending DHCP_DISCOVER packet:")
    packet = DHCP_PACKET(None)
    packet.opcode = DHCP_Opcode.REQUEST
    packet.message_type = DHCP_Message_Type.DHCP_DISCOVER

    print(packet)
    message = packet.encode()
    sock.sendto(message, dst)

    log.info("UDP target ip {}".format(UDP_IP))
    log.info("UDP target port {}".format(UDP_PORT))

    try:
        while True:
            r, _, _ = select.select([sock], [], [], 3)
            if not r:
                log.info("Nu s-a receptionat nimic de la server")
                break
            else:
                data = sock.recv(MAX_BYTES)
                packet_received = DHCP_PACKET(data)
                if packet_received.message_type == DHCP_Message_Type.DHCP_OFFER:
                    log.info("Offer received")
                    packet_received.message_type = DHCP_Message_Type.DHCP_REQUEST
                    packet_received.opcode = DHCP_Opcode.REQUEST

                    sock.sendto(packet_received.encode(), dst)
                elif packet_received.message_type == DHCP_Message_Type.DHCP_ACK:
                    log.info("Acknowledge received")
                elif packet_received.message_type == DHCP_Message_Type.DHCP_NAK:
                    log.info("Negative Acknowledge received")
                print(packet_received)
    except socket.timeout as e:
        print("Timpul de asteptare a expirat.")
        sock.close()
        exit(1)
    sock.close()


def client_2():
    dst = ('<broadcast>', serverPort)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, clientPort))

    log.info("Sending DHCP_DISCOVER packet:")

    #Here we manipulate our packet
    packet = DHCP_PACKET(None)
    packet.opcode = DHCP_Opcode.REQUEST
    packet.message_type = DHCP_Message_Type.DHCP_REQUEST
    packet.client_hardware_address = '00:00:00:00:00:09'
    packet.your_ip_address = '10.1.0.124'

    print(packet)
    message = packet.encode()
    sock.sendto(message, dst)

    log.info("UDP target ip {}".format(UDP_IP))
    log.info("UDP target port {}".format(UDP_PORT))

    try:
        while True:
            r, _, _ = select.select([sock], [], [], 3)
            if not r:
                log.info("Nu s-a receptionat nimic de la server")
                break
            else:
                data = sock.recv(MAX_BYTES)
                packet_received = DHCP_PACKET(data)
                if packet_received.message_type == DHCP_Message_Type.DHCP_OFFER:
                    log.info("Offer received")
                elif packet_received.message_type == DHCP_Message_Type.DHCP_ACK:
                    log.info("Acknowledge received")
                elif packet_received.message_type == DHCP_Message_Type.DHCP_NAK:
                    log.info("Negative Acknowledge received")
                print(packet_received)
    except socket.timeout as e:
        print("Timpul de asteptare a expirat.")
        sock.close()
        exit(1)
    sock.close()


if __name__=='__main__':
    #client_1()
    client_2()
