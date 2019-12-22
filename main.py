from dhcp_gui import DHCP_Server_GUI
from dhcp_packet import *


def start_gui():
    app = DHCP_Server_GUI()
    app.geometry("800x600")
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


def main():
    #dhcp_server = DHCP_Server()
    #dhcp_server.start_server()
    start_gui()


if __name__ == '__main__':
    main()

