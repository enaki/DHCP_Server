import re
import socket
import sys
import threading
import tkinter as tk
from tkinter import ttk
from abc import abstractmethod
from tkinter import font as tkfont, messagebox
import logging as log
from dhcp_server import DHCP_Server

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
        self.show_frame("ServerConfigurationsPage")

    def update_frames_address_pool(self):
        self.frames["ServerStartPage"].addr_pool_text_widget_fill()
        self.frames["ServerConfigurationsPage"].static_ip_combobox.configure(
            values=[ip for ip, ip_info in self.dhcp_server.address_pool.items() if ip_info['mac'] is None])

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


class ServerPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#101010")
        self.controller = controller
        self.other_page = None

    def set_other_page(self, other_page):
        self.other_page = other_page

    @abstractmethod
    def addr_pool_text_widget_fill(self):
        pass


class ServerStartPage(ServerPage):
    def __init__(self, parent, controller):
        ServerPage.__init__(self, parent, controller)
        self.init_window()

    def init_window(self, button_bg='#222222', button_fg='#ffffff', label_bg='#303030', label_txt='yellow', txt_color='#00FF41', text_widget_width= 75):
        # --------------------------------TOP FRAME----------------------------------
        tk.Label(master=self, text='DHCP SERVER', bg=self["bg"], fg=label_txt,font=self.controller.title_font).pack(side=tk.TOP)

        # --------------------------------BOTTOM FRAME----------------------------------
        server_frame = tk.Frame(master=self, bg="#050505")
        server_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=0)

        # Space for Server configurations Button
        tk.Grid.columnconfigure(server_frame, 0, weight=1)

        tk.Button(server_frame, text="Server Configurations", width=20, bg=button_bg, fg=button_fg, command=lambda: self.controller.show_frame("ServerConfigurationsPage")).grid(row=0, column=0, padx=5, pady=5)
        self.start_server_button = tk.Button(server_frame, text="Start Server", width=10, bg=button_bg, fg=button_fg, command=self.start_server, font=self.controller.button_text_font)
        self.start_server_button.grid(row=0, column=1, padx=5, pady=5)
        self.start_server_button['state'] = tk.DISABLED

        self.stop_server_button = tk.Button(server_frame, text="Stop Server", width=10, bg=button_bg, fg=button_fg, command=self.stop_server, font=self.controller.button_text_font)
        self.stop_server_button.grid(row=0, column=2, padx=5, pady=5)
        self.stop_server_button['state'] = tk.DISABLED

        tk.Button(server_frame, text="Close", width=10, command=self.controller.gui_exit, bg=button_bg, fg=button_fg, font=self.controller.button_text_font) \
            .grid(row=0, column=3, padx=5, pady=5)

        # --------------------------------RIGHT FRAME-----------------------------------
        server_info_frame = tk.Frame(master=self, bg="#101010")
        server_info_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=1, padx=5, pady=5)

        #------Server Info
        server_info_label = tk.LabelFrame(server_info_frame, text="Server Info", bg=label_bg, fg=label_txt, font=self.controller.text_label_title)
        server_info_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.server_name_label_var = tk.StringVar()
        self.server_name_label_var.set("unknown")
        tk.Label(server_info_label, text="Server Name: ", bg=server_info_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=0, column=0, sticky='w')
        tk.Label(server_info_label, textvariable=self.server_name_label_var, bg=server_info_label["bg"], fg=button_fg, font=self.controller.text_label).grid(row=0, column=1, sticky='w')

        self.lease_time_label_var = tk.StringVar()
        self.lease_time_label_var.set("unknown")
        tk.Label(server_info_label, text="Lease Time: ", bg=server_info_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=1, column=0, sticky='w')
        tk.Label(server_info_label, textvariable=self.lease_time_label_var, bg=server_info_label["bg"], fg=button_fg, font=self.controller.text_label).grid(row=1, column=1, sticky='w')
        #------Addres pool info
        address_pool_label = tk.LabelFrame(server_info_frame, text="Address Pool", bg=label_bg, fg='yellow', font=self.controller.text_label_title)
        address_pool_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.ip_address_label_var = tk.StringVar()
        self.ip_address_label_var.set("unknown")
        tk.Label(address_pool_label, text="IP Address: ", bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=0, column=0, sticky='w')
        tk.Label(address_pool_label, textvariable=self.ip_address_label_var, bg=address_pool_label["bg"], fg=button_fg,
                 font=self.controller.text_label).grid(row=0, column=1, sticky='w')

        self.mask_label_var = tk.StringVar()
        self.mask_label_var.set("unknown")
        tk.Label(address_pool_label, text="Mask: ", bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=1, column=0, sticky='w')
        tk.Label(address_pool_label, textvariable=self.mask_label_var, bg=address_pool_label["bg"], fg=button_fg,
                 font=self.controller.text_label).grid(row=1, column=1, sticky='w')

        # --------------------------------LEFT FRAME----------------------------------
        address_pool_frame = tk.Frame(master=self, bg="#101010")
        address_pool_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=5, pady=5)

        address_pool_viewer_label = tk.LabelFrame(address_pool_frame, text="Address Pool Viewer", bg=label_bg, fg='yellow', font=self.controller.text_label_title)
        address_pool_viewer_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')

        self.ip_address_pool_text = tk.Text(address_pool_viewer_label, height=10, width=text_widget_width, wrap='none', bg='black', fg='light green', padx=5, pady=5)
        ip_address_pool_scroll_y = tk.Scrollbar(address_pool_viewer_label, command=self.ip_address_pool_text.yview)
        ip_address_pool_scroll_x = tk.Scrollbar(address_pool_viewer_label, command=self.ip_address_pool_text.xview, orient='horizontal')
        self.ip_address_pool_text['yscrollcommand'] = ip_address_pool_scroll_y.set
        self.ip_address_pool_text['xscrollcommand'] = ip_address_pool_scroll_x.set
        self.ip_address_pool_text.grid(row=0, column=0, sticky=tk.N+tk.S)
        ip_address_pool_scroll_y.grid(row=0, column=1, sticky=tk.N+tk.S+tk.W)
        ip_address_pool_scroll_x.grid(row=1, sticky=tk.N+tk.E+tk.W)

        self.ip_address_pool_text.tag_configure('bold_title', font=('Times', 12, 'bold'))
        self.ip_address_pool_text.tag_configure('text', font=('Times', 12))

        address_server_status_label = tk.LabelFrame(address_pool_frame, text="Server Status", bg=label_bg, fg='yellow', font=self.controller.text_label_title)
        address_server_status_label.grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.server_status_text = tk.Text(address_server_status_label, height=20, width=text_widget_width, wrap='none', bg='black', fg='light gray', padx=5, pady=5)
        server_status_scroll_y = tk.Scrollbar(address_server_status_label, command=self.server_status_text.yview)
        server_status_scroll_x = tk.Scrollbar(address_server_status_label, command=self.server_status_text.xview, orient='horizontal')
        self.server_status_text['yscrollcommand'] = server_status_scroll_y.set
        self.server_status_text['xscrollcommand'] = server_status_scroll_x.set
        self.server_status_text.grid(row=0, column=0, columnspan=2, sticky=tk.N + tk.S)
        server_status_scroll_y.grid(row=0, column=2, sticky=tk.N + tk.S + tk.W)
        server_status_scroll_x.grid(row=1, columnspan=2, sticky=tk.N + tk.E + tk.W)
        self.server_status_text.tag_configure('bold_title', font=('Times', 11, 'bold'))
        self.server_status_text.tag_configure('text', font=('Times', 11))

        tk.Button(address_server_status_label, text="Save Histo", width=10, command=self.file_save, bg=button_bg, fg=button_fg, font=self.controller.button_text_font) \
            .grid(row=2, column=0, padx=5, pady=5)
        self.show_packets = tk.IntVar()
        self.show_packets_ch_btn = tk.Checkbutton(address_server_status_label, text="Show Packets", onvalue=1, offvalue=0, command=self.packet_info, variable=self.show_packets, bg=address_server_status_label["bg"], fg='white')
        self.show_packets_ch_btn.grid(row=2, column=1, padx=5, pady=5)

    def file_save(self):
        f = open("dhcp_histo.txt", "w")
        text2save = str(self.server_status_text.get(1.0, tk.END))  # starts from `1.0`, not `0.0`
        f.write(text2save)
        f.close()

    def packet_info(self):
        if self.show_packets.get() == 1:
            self.show_packets_ch_btn["fg"] = 'cyan'
            self.controller.dhcp_server.show_packets_debug = True
        else:
            self.show_packets_ch_btn["fg"] = 'white'
            self.controller.dhcp_server.show_packets_debug = False

    def start_server(self):
        self.start_server_button['state'] = tk.DISABLED
        self.stop_server_button['state'] = tk.NORMAL
        self.other_page.set_pool_address_button['state'] = tk.DISABLED
        self.controller.start_server()

    def activate_start_button(self):
        while self.controller.dhcp_server.server_is_shut_down is not True:
            pass
        self.start_server_button['state'] = tk.NORMAL

    def stop_server(self):
        self.stop_server_button['state'] = tk.DISABLED
        self.other_page.set_pool_address_button['state'] = tk.NORMAL
        self.controller.stop_server()
        activate_btn_thread = threading.Thread(target=self.activate_start_button)
        activate_btn_thread.daemon = True
        activate_btn_thread.start()

    def addr_pool_text_widget_fill(self):
        self.ip_address_pool_text.delete(1.0, tk.END)
        self.ip_address_pool_text.insert(tk.END, "Net Address : ", 'bold_title')
        self.ip_address_pool_text.insert(tk.END, "{}\n".format(self.controller.dhcp_server.address_pool_starting_ip_address), 'text')
        self.ip_address_pool_text.insert(tk.END, "Broadcast Address : ", 'bold_title')
        self.ip_address_pool_text.insert(tk.END, "{}\n".format(
        self.controller.dhcp_server.address_pool_broadcast), 'text')
        self.ip_address_pool_text.insert(tk.END, "IP\t\tMAC\t\tLease Time\n", 'bold_title')

        for key, value in self.controller.dhcp_server.address_pool.items():
            self.ip_address_pool_text.insert(tk.END, "{}\t\t{}\t\t{}\n".format(key, value['mac'], value['time'].strftime("%m/%d/%Y, %H:%M:%S") if value['time'] is not None else "None"), 'text')


class ServerConfigurationsPage(ServerPage):
    def __init__(self, parent, controller):
        ServerPage.__init__(self, parent, controller)
        self.init_window()

    def init_window(self, button_bg='#222222', button_fg='#ffffff', label_bg='#303030', label_txt='yellow', txt_color='#00FF41'):
        #--------------------------------TOP FRAME----------------------------------
        tk.Label(master=self, text='DHCP SERVER Configurations', bg=self["bg"], fg=label_txt, font=self.controller.title_font).pack(side=tk.TOP)

        #--------------------------------BOTTOM FRAME----------------------------------
        server_frame = tk.Frame(master=self, bg="#050505")
        server_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=0)

        #Space for Server configurations Button
        tk.Grid.columnconfigure(server_frame, 0, weight=1)
        tk.Button(server_frame, text="Server Start Page", width=20, bg=button_bg, fg=button_fg, font=self.controller.button_text_font,
                  command=lambda: self.controller.show_frame("ServerStartPage")).grid(row=0, column=0, padx=5, pady=5)

        # --------------------------------LEFT FRAME----------------------------------
        address_pool_frame = tk.Frame(master=self, bg="#101010")
        address_pool_frame.pack(side=tk.LEFT, fill=tk.Y, expand=1)

        address_pool_label = tk.LabelFrame(address_pool_frame, text="Address Pool", bg=label_bg, fg=label_txt, font=self.controller.text_label_title)
        address_pool_label.grid(row=0, column=0, padx=10, pady=10)

        tk.Label(address_pool_label, text='IP Address', bg=address_pool_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=0, column=0)
        self.ip_address_entry = tk.Entry(address_pool_label, width=30)
        self.ip_address_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Label(address_pool_label, text='Mask', bg=address_pool_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=1, column=0)
        self.mask_entry = ttk.Combobox(address_pool_label, width=27, values=["/{}".format(str(x)) for x in range(16, 31)])
        self.mask_entry.grid(row=1, column=1, padx=5, pady=5)

        self.ip_address_entry.insert(0, '10.1.0.127')
        self.mask_entry.insert(0, '/29')
        self.set_pool_address_button = tk.Button(address_pool_label, text='Set Pool Address', command=self.set_pool_address, bg=button_bg, fg=button_fg, font=self.controller.button_text_font)
        self.set_pool_address_button.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(address_pool_label, text='View Pool Address', command=self.addr_pool_text_widget_fill, bg=button_bg,
                  fg=button_fg, font=self.controller.button_text_font).grid(row=2, column=0, padx=5, pady=5)

        address_pool_viewer_label = tk.LabelFrame(address_pool_frame, text="Address Pool Viewer", bg=label_bg, fg='yellow', font=self.controller.text_label_title)
        address_pool_viewer_label.grid(row=1, column=0, padx=10, pady=10, sticky='w')

        self.ip_address_pool_text = tk.Text(address_pool_viewer_label, height=10, width=50, bg="#101010", fg='light green')
        ip_address_pool_scroll = tk.Scrollbar(address_pool_viewer_label, command=self.ip_address_pool_text.yview)
        self.ip_address_pool_text['yscrollcommand'] = ip_address_pool_scroll.set
        self.ip_address_pool_text.grid(row=0, column=0, sticky=tk.N+tk.S)
        ip_address_pool_scroll.grid(row=0, column=1, sticky=tk.N+tk.S+tk.W)

        # --------------------------------RIGHT FRAME----------------------------------
        widget_frame = tk.Frame(master=self, bg="#101010")
        widget_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=1)

        #set server name
        server_name_label_frame = tk.LabelFrame(widget_frame, text="Server Name", bg=label_bg, fg=label_txt, font=self.controller.text_label_title)
        server_name_label_frame.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        tk.Label(server_name_label_frame, text='Server Name', bg=address_pool_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=0, column=0)
        self.server_name_entry = tk.Entry(server_name_label_frame, width=30)
        self.server_name_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(server_name_label_frame, text='Set Server Name', bg=button_bg, fg=button_fg, font=self.controller.button_text_font, command=self.set_server_name).grid(row=2, padx=5, pady=5, columnspan=2)

        #Set Lease Time
        lease_time_label_frame = tk.LabelFrame(widget_frame, text="Lease Time", bg='#303030', fg='yellow', font=self.controller.text_label_title)
        lease_time_label_frame.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        tk.Label(lease_time_label_frame, text='Lease Time', bg=address_pool_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=1, column=0)
        self.lease_time_entry = ttk.Combobox(lease_time_label_frame, width=29, values=[600, 1200, 1800, 3600])
        self.lease_time_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(lease_time_label_frame, text='Set Lease Time', bg=button_bg, fg=button_fg, font=self.controller.button_text_font, command=self.set_server_lease_time).grid(row=2, padx=5, pady=5, columnspan=2)
        self.server_name_entry.insert(0, "DHCP Server")
        self.lease_time_entry.insert(0, "600")

        # allocate static ip
        static_ip_alloc_frame = tk.LabelFrame(widget_frame, text="Static IP Allocation", bg=label_bg, fg=label_txt, font=self.controller.text_label_title)
        static_ip_alloc_frame.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        tk.Label(static_ip_alloc_frame, text='IP Address', bg=address_pool_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=0, column=0)
        self.static_ip_combobox = ttk.Combobox(static_ip_alloc_frame, width=30, values=[])

        self.static_ip_combobox.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Label(static_ip_alloc_frame, text='MAC', bg=address_pool_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=1, column=0)
        self.mac_entry = tk.Entry(static_ip_alloc_frame, width=30)
        self.mac_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(static_ip_alloc_frame, text='Set IP Address', bg=button_bg, fg=button_fg,
                  font=self.controller.button_text_font, command=self.set_static_ip).grid(row=2, padx=5, pady=5,
                                                                                            columnspan=2)

    def set_static_ip(self):
        ip = self.static_ip_combobox.get()
        dict = self.controller.dhcp_server.address_pool
        if ip not in dict:
            messagebox.showinfo("IP missing error", "IP not in DHCP Server Address Pool")
            return
        if dict[ip]['mac'] is not None:
            messagebox.showinfo("IP taken error", "IP {} is already taken".format(ip))
            return
        mac_unk = (self.mac_entry.get()).lower()
        mac_checker = lambda mac: re.match("([0-9a-f]{2}[:]){5}([0-9a-f]{2})", mac)
        if mac_checker(mac_unk) is None:
            messagebox.showinfo("MAC format error", "MAC format is xx:xx:xx:xx:xx:xx where x in [0-9a-f]")
            return
        if any(mac_unk in ip_info.values() for ip_info in self.controller.dhcp_server.address_pool.values()):
            messagebox.showinfo("Address Pool Error", "This mac already holds an ip address")
            return
        self.controller.dhcp_server.address_pool.update({ip: {'mac': mac_unk, 'time': None}})
        self.addr_pool_text_widget_fill()
        self.other_page.addr_pool_text_widget_fill()

        self.static_ip_combobox.configure(
            values=[ip for ip, ip_info in self.controller.dhcp_server.address_pool.items() if ip_info['mac'] is None])


    @staticmethod
    def _get_ip_network_of_ipv4(ipv4, mask):
        import ipaddress
        return str(ipaddress.ip_interface(ipv4 + '/' + str(mask)).network).split('/')[0]

    @staticmethod
    def _check_pool_is_correct(ip, mask):
        socket.inet_aton(ip)
        if mask == '':
            raise ValueError
        if mask[0] == '/':
            mask_result = int(mask[1:])
        else:
            mask_result = int(mask)
        if mask_result < 1 or mask_result > 32:
            raise ValueError
        return mask_result

    def set_pool_address(self):
        mask = self.mask_entry.get()
        ip = self.ip_address_entry.get()
        self.controller.dhcp_server.debug("Set pool address")
        try:
            mask_result = self._check_pool_is_correct(ip, mask)
            starting_ip = self._get_ip_network_of_ipv4(ip, mask_result)
            self.other_page.ip_address_label_var.set(starting_ip)
            self.other_page.mask_label_var.set("/{}".format(mask_result))
            self.controller.dhcp_server.set_address_pool_config(starting_ip, mask_result)
            self.controller.dhcp_server.set_address_pool()

            #self.addr_pool_text_widget_fill()
            self.controller.update_frames_address_pool()
            if self.other_page.server_name_label_var.get() != "unknown" and self.other_page.lease_time_label_var != "unknown":
                self.other_page.start_server_button['state'] = tk.NORMAL
        except socket.error:
            messagebox.showinfo("IP Format error", "IP Format: x.x.x.x where x = 0-255")
        except ValueError:
            messagebox.showinfo("Mask Format error", "Mask Format: x or \\x, where x = 1-32")

    def addr_pool_text_widget_fill(self):
        mask = self.mask_entry.get()
        ip = self.ip_address_entry.get()
        self.controller.dhcp_server.debug("View pool address")
        mask_result = self._check_pool_is_correct(ip, mask)
        starting_ip = self._get_ip_network_of_ipv4(ip, mask_result)
        address_pool, address_pool_broadcast = DHCP_Server.calculate_address_pool(starting_ip, mask_result)

        self.ip_address_pool_text.delete(1.0, tk.END)
        self.ip_address_pool_text.insert(tk.END, "Net Address : {}\n".format(starting_ip))
        self.ip_address_pool_text.insert(tk.END, "Broadcast Address : {}\n".format(address_pool_broadcast))
        for key, value in address_pool.items():
            self.ip_address_pool_text.insert(tk.END, key + '\n')

    def set_server_name(self):
        server_name = self.server_name_entry.get()
        self.controller.dhcp_server.debug("Set Server Name '{}'".format(server_name))
        self.other_page.server_name_label_var.set(server_name)
        self.controller.dhcp_server.set_server_name(server_name)
        if self.other_page.mask_label_var.get() != "unknown" and self.other_page.lease_time_label_var.get() != "unknown":
            self.other_page.start_server_button['state'] = tk.NORMAL

    def set_server_lease_time(self):
        lease_time = self.lease_time_entry.get()
        self.controller.dhcp_server.debug("Set Lease Time {}".format(lease_time))
        import time
        self.other_page.lease_time_label_var.set("{} days {}".format(int(lease_time) // 86400, time.strftime('%H:%M:%S', time.gmtime(int(lease_time)))))
        self.controller.dhcp_server.set_server_lease_time(int(lease_time))
        if self.other_page.server_name_label_var.get() != "unknown" and self.other_page.mask_label_var.get() != "unknown":
            self.other_page.start_server_button['state'] = tk.NORMAL
