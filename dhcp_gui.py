import sys
import threading
import tkinter as tk
from tkinter import font as tkfont
import logging as log
from dhcp_server import DHCP_Server
from gui_pages.server_configurations_page import ServerConfigurationsPage
from gui_pages.server_start_page import ServerStartPage

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)


class DHCP_Server_GUI(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold")
        self.text_label_title = tkfont.Font(family='Helvetica', size=12)
        self.button_text_font = tkfont.Font(family='Times', size=11)
        self.text_label = tkfont.Font(family='Arial', size=11)
        # the container is where we'll stack a bunch of frames
        # on top of each other, then the one we want visible
        # will be raised above the others
        self.title("DHCP SERVER")
        container = tk.Frame(self)
        container.pack(side="top", fill=tk.BOTH, expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self.dhcp_server = DHCP_Server(self)
        for F in (ServerStartPage, ServerConfigurationsPage):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")
        self.frames['ServerStartPage'].set_other_page(self.frames['ServerConfigurationsPage'])
        self.frames['ServerConfigurationsPage'].set_other_page(self.frames['ServerStartPage'])
        self.show_frame("ServerStartPage")

    def update_frames_address_pool(self):
        self.frames["ServerStartPage"].addr_pool_text_widget_fill()
        self.frames["ServerStartPage"].static_ip_combobox.configure(
            values=[ip for ip, ip_info in self.dhcp_server.address_pool.items() if ip_info['mac'] is None])
        self.frames["ServerStartPage"].release_ip_combobox.configure(
            values=[ip for ip, ip_info in self.dhcp_server.address_pool.items() if ip_info['mac'] is not None])

    def start_server(self):
        self.server_thread = threading.Thread(target=self.dhcp_server.start_server)
        self.server_thread.daemon = True
        self.dhcp_server.set_flag(True)
        self.server_thread.start()

    def stop_server(self):
        self.dhcp_server.set_flag(False)

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()

    def gui_exit(self):
        self.dhcp_server.debug('Stopping Server')
        self.dhcp_server.set_flag(1)
        exit()

