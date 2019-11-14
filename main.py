import socket
import tkinter as tk
import logging as log
from dhcp_gui import DHCP_Server_GUI
from dhcp_server import DHCP_Server


def start_gui(self):
    root = tk.Tk()
    root.geometry("800x500")
    app = DHCP_Server_GUI(root)
    root.mainloop()

if __name__ == '__main__':
    server = DHCP_Server()
    #server.start_gui()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    

