from dhcp_gui import DHCP_Server_GUI
from dhcp_packet import *


def start_gui():
    app = DHCP_Server_GUI()
    app.geometry("1024x800")
    app.mainloop()


def test_Encoder():
    ip = '10.14.15.16'
    print(list(Encoder.ip(ip)))
    val = 255
    print(Encoder.int(val))
    mac = '04:03:ab:43'
    print(Encoder.mac(mac))
    mac2 = 0x129354
    print(Encoder.hex(mac2, 10))


def test_Decoder():
    ip = b'\x12\x34\x56\67'
    print(Decoder.ip(ip))
    mac = b'\x34\x01\x02\x03\x45\x67'
    print(Decoder.mac(mac))
    print(Decoder.str(mac))


def test_Packet():
    packet = DHCP_PACKET(None, lease_time=600)
    packet.opcode = DHCP_Opcode.REQUEST
    packet.message_type = DHCP_Message_Type.DHCP_ACK
    packet.dns = 'host.ro'
    packet.router = '127.0.0.1'
    packet.server_name = 'Greg'
    packet.broadcast_address = '10.0.1.255'
    req_list = [DHCP_Options.OP_ROUTER, DHCP_Options.OP_SERVER_NAME, DHCP_Options.OP_BROADCAST_ADDRESS]
    packet.request_options = req_list
    packet.server_mode = True
    print(packet)
    data = packet.encode()

    new_packet = DHCP_PACKET(data)
    print(new_packet)


def main():
    #test_Packet()

    #run server without interface, server_name, address_pool and lease_time need to be set
    #dhcp_server = DHCP_Server()
    #dhcp_server.start_server()

    #start server with gui
    start_gui()


if __name__ == '__main__':
    main()
