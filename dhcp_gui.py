import tkinter as tk
from tkinter import font as tkfont
import logging as log


class DHCP_Server_GUI(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold")

        # the container is where we'll stack a bunch of frames
        # on top of each other, then the one we want visible
        # will be raised above the others
        self.title("DHCP SERVER")
        container = tk.Frame(self)
        container.pack(side="top", fill=tk.BOTH, expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (ServerStartPage, ServerConfigurationsPage):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame

            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("ServerStartPage")

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()

    @staticmethod
    def gui_exit():
        log.info('Stopping Server')
        exit()


class ServerStartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#101010")
        self.controller = controller
        self.init_window()

    def init_window(self):
        # --------------------------------TOP FRAME----------------------------------
        tk.Label(master=self, text='DHCP SERVER', bg=self["bg"], fg='yellow',
                 font=self.controller.title_font).pack(side=tk.TOP)

        # --------------------------------BOTTOM FRAME----------------------------------
        server_frame = tk.Frame(master=self, bg="#050505")
        server_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=0)

        # Space for Server configurations Button
        tk.Grid.columnconfigure(server_frame, 0, weight=1)

        tk.Button(server_frame, text="Server Configurations", width=20, bg='#222222', fg='#ffffff',
                  command=lambda: self.controller.show_frame("ServerConfigurationsPage")).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(server_frame, text="Start Server", width=10, bg='#222222', fg='#ffffff') \
            .grid(row=0, column=1, padx=5, pady=5)
        tk.Button(server_frame, text="Stop Server", width=10, bg='#222222', fg='#ffffff') \
            .grid(row=0, column=2, padx=5, pady=5)
        tk.Button(server_frame, text="Close", width=10, command=DHCP_Server_GUI.gui_exit, bg='#222222', fg='#ffffff') \
            .grid(row=0, column=3, padx=5, pady=5)

        # --------------------------------LEFT FRAME-----------------------------------
        server_info_frame = tk.Frame(master=self, bg="#101010")
        server_info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=5, pady=5)
        server_info_label = tk.LabelFrame(server_info_frame, text="Server Info", bg='#303030', fg='yellow')
        server_info_label.grid(row=0, column=0, padx=10, pady=10)
        tk.Label(server_info_label, text='Server Name: ', bg=server_info_label["bg"], fg='#00FF41').grid(row=0, column=0, sticky='w')
        tk.Label(server_info_label, text='Lease Time: ', bg=server_info_label["bg"], fg='#00FF41').grid(row=1, column=0, sticky='w')

        # --------------------------------RIGHT FRAME----------------------------------
        address_pool_frame = tk.Frame(master=self, bg="#101010")
        address_pool_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=1)

        address_pool_label = tk.LabelFrame(address_pool_frame, text="Address Pool", bg='#303030', fg='yellow')
        address_pool_label.grid(row=0, column=0, padx=10, pady=10)

        tk.Label(address_pool_label, text='IP Address: ', bg=address_pool_label["bg"], fg='#00FF41').grid(row=0, column=0, sticky='w')
        tk.Label(address_pool_label, text='Mask: ', bg=address_pool_label["bg"], fg='#00FF41').grid(row=1, column=0, sticky='w')

        ip_address_pool_scroll = tk.Scrollbar(address_pool_frame)
        ip_address_pool_text = tk.Text(address_pool_frame, height=4, width=40)
        ip_address_pool_text.grid(row=2, column=0, sticky=tk.N+tk.S)
        ip_address_pool_scroll.grid(row=2, column=1, sticky=tk.N+tk.S+tk.W)


class ServerConfigurationsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#101010")
        self.controller = controller
        self.init_window()

    def init_window(self):
        #--------------------------------TOP FRAME----------------------------------
        tk.Label(master=self, text='DHCP SERVER Configurations', bg=self["bg"], fg='yellow',
                 font=self.controller.title_font).pack(side=tk.TOP)

        #--------------------------------BOTTOM FRAME----------------------------------
        server_frame = tk.Frame(master=self, bg="#050505")
        server_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=0)

        #Space for Server configurations Button
        tk.Grid.columnconfigure(server_frame, 0, weight=1)

        tk.Button(server_frame, text="Server Start Page", width=20, bg='#222222', fg='#ffffff',
                  command=lambda: self.controller.show_frame("ServerStartPage")).grid(row=0, column=0, padx=5, pady=5)

        # --------------------------------LEFT FRAME----------------------------------
        address_pool_frame = tk.Frame(master=self, bg="#101010")
        address_pool_frame.pack(side=tk.LEFT, fill=tk.Y, expand=1)

        address_pool_label = tk.LabelFrame(address_pool_frame, text="Address Pool", bg='#303030', fg='yellow')
        address_pool_label.grid(row=0, column=0, padx=10, pady=10)

        tk.Label(address_pool_label, text='IP Address', bg=address_pool_label["bg"], fg='#00FF41').grid(row=0, column=0)
        tk.Entry(address_pool_label, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Label(address_pool_label, text='Mask', bg=address_pool_label["bg"], fg='#00FF41').grid(row=1, column=0)
        tk.Entry(address_pool_label, width=30).grid(row=1, column=1, padx=5, pady=5)

        tk.Button(address_pool_label, text='Set Pool Address', bg='#222222',
                  fg='#ffffff').grid(row=2, padx=5, pady=5, columnspan=2)

        ip_address_pool_scroll = tk.Scrollbar(address_pool_frame)
        ip_address_pool_text = tk.Text(address_pool_frame, height=4, width=40)
        ip_address_pool_text.grid(row=3, column=0, sticky=tk.N+tk.S)
        ip_address_pool_scroll.grid(row=3, column=1, sticky=tk.N+tk.S+tk.W)

        # --------------------------------RIGHT FRAME----------------------------------
        widget_frame = tk.Frame(master=self, bg="#101010")
        widget_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=1)

        #set server name
        server_name_label_frame = tk.LabelFrame(widget_frame, text="Server Name", bg='#303030', fg='yellow')
        server_name_label_frame.grid(row=0, column=0, padx=10, pady=10)
        tk.Label(server_name_label_frame, text='Server Name', bg=address_pool_label["bg"], fg='#00FF41').grid(row=0,
                                                                                                            column=0)
        tk.Entry(server_name_label_frame, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(server_name_label_frame, text='Set Server Name', bg='#222222',
                  fg='#ffffff').grid(row=2, padx=5, pady=5, columnspan=2)

        #Set Lease Time
        lease_time_label_frame = tk.LabelFrame(widget_frame, text="Lease Time", bg='#303030', fg='yellow')
        lease_time_label_frame.grid(row=1, column=0, padx=10, pady=10)
        tk.Label(lease_time_label_frame, text='Lease Time', bg=address_pool_label["bg"], fg='#00FF41').grid(row=1,
                                                                                                            column=0)
        tk.Entry(lease_time_label_frame, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(lease_time_label_frame, text='Set Lease Time', bg='#222222',
                  fg='#ffffff').grid(row=2, padx=5, pady=5, columnspan=2)




