import socket
import tkinter as tk
import logging as log
from dhcp_gui import DHCP_Server_GUI
from dhcp_packet import Encoder, DHCP_PACKET, Decoder
from dhcp_server import DHCP_Server


def start_gui():
    root = tk.Tk()
    root.geometry("800x500")
    app = DHCP_Server_GUI(root)
    root.mainloop()

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

def Main():
    server = DHCP_Server()
    #start_gui()
    #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #test_Encoder()
    #test_Decoder()
    #plg = DHCP_PACKET()
    p = DHCP_PACKET(None)
    print(p)
    data = p.encode()
    print(data)
    p2 = DHCP_PACKET(data)
    print(p2)
    #print(plg.encode())

if __name__ == '__main__':
    Main()

