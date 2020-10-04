import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from gui_pages.server_basic_page import ServerPage


class ServerStartPage(ServerPage):
    def __init__(self, parent, controller):
        ServerPage.__init__(self, parent, controller)
        self.init_window()

    def init_window(self, button_bg='#222222', button_fg='#ffffff', label_bg='#303030', label_txt='yellow', txt_color='#00FF41', text_widget_width=75):
        # --------------------------------TOP FRAME----------------------------------
        tk.Label(master=self, text='DHCP SERVER', bg=self["bg"], fg=label_txt, font=self.controller.title_font).pack(side=tk.TOP)

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
        tk.Label(server_info_label, textvariable=self.server_name_label_var, bg=server_info_label["bg"], fg=button_fg, font=self.controller.text_label, width=20).grid(row=0, column=1, sticky='w')

        self.lease_time_label_var = tk.StringVar()
        self.lease_time_label_var.set("unknown")
        tk.Label(server_info_label, text="Lease Time: ", bg=server_info_label["bg"], fg=txt_color, font=self.controller.text_label).grid(row=1, column=0, sticky='w')
        tk.Label(server_info_label, textvariable=self.lease_time_label_var, bg=server_info_label["bg"], fg=button_fg, font=self.controller.text_label, width=20).grid(row=1, column=1, sticky='w')

        self.router_level_var = tk.StringVar()
        self.router_level_var.set(self.controller.dhcp_server.router)
        tk.Label(server_info_label, text="Router: ", bg=server_info_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=2, column=0, sticky='w')
        tk.Label(server_info_label, textvariable=self.router_level_var, bg=server_info_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=20).grid(row=2, column=1, sticky='w')

        self.dns_lavel_var = tk.StringVar()
        self.dns_lavel_var.set(self.controller.dhcp_server.dns)
        tk.Label(server_info_label, text="DNS: ", bg=server_info_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=3, column=0, sticky='w')
        tk.Label(server_info_label, textvariable=self.dns_lavel_var, bg=server_info_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=20).grid(row=3, column=1, sticky='w')

        #------Addres pool info
        address_pool_label = tk.LabelFrame(server_info_frame, text="Address Pool", bg=label_bg, fg='yellow', font=self.controller.text_label_title)
        address_pool_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.ip_address_label_var = tk.StringVar()
        self.ip_address_label_var.set("unknown")
        tk.Label(address_pool_label, text="Network IP Address: ", bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=0, column=0, sticky='w')
        tk.Label(address_pool_label, textvariable=self.ip_address_label_var, bg=address_pool_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=15).grid(row=0, column=1, sticky='w')

        self.mask_label_var = tk.StringVar()
        self.mask_label_var.set("unknown")
        tk.Label(address_pool_label, text="Mask: ", bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=1, column=0, sticky='w')
        tk.Label(address_pool_label, textvariable=self.mask_label_var, bg=address_pool_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=15).grid(row=1, column=1, sticky='w')

        # allocate static ip
        static_ip_alloc_frame = tk.LabelFrame(server_info_frame, text="Static IP Allocation", bg=label_bg, fg=label_txt,
                                              font=self.controller.text_label_title)
        static_ip_alloc_frame.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        tk.Label(static_ip_alloc_frame, text='IP Address', bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=0, column=0)
        self.static_ip_combobox = ttk.Combobox(static_ip_alloc_frame, width=30, values=[])

        self.static_ip_combobox.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Label(static_ip_alloc_frame, text='MAC', bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=1, column=0)
        self.mac_entry = tk.Entry(static_ip_alloc_frame, width=30)
        self.mac_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(static_ip_alloc_frame, text='Set IP Address', bg=button_bg, fg=button_fg,
                  font=self.controller.button_text_font, command=self.set_static_ip).grid(row=2, padx=5, pady=5,
                                                                                          columnspan=2)
        # release ip
        release_ip_frame = tk.LabelFrame(server_info_frame, text="Release IP", bg=label_bg, fg=label_txt,
                                         font=self.controller.text_label_title)
        release_ip_frame.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        tk.Label(release_ip_frame, text='IP Address', bg=address_pool_label["bg"], fg=txt_color,
                 font=self.controller.text_label).grid(row=0, column=0)
        self.release_ip_combobox = ttk.Combobox(release_ip_frame, width=30, values=[])
        self.release_ip_combobox.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.mac_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        tk.Button(release_ip_frame, text='Release IP Address', bg=button_bg, fg=button_fg,
                  font=self.controller.button_text_font, command=self.release_ip_address).grid(row=2, padx=5, pady=5,
                                                                                               columnspan=2)

        #projet info
        project_info_label = tk.LabelFrame(server_info_frame, text="Project Info", bg=label_bg, fg='orange',
                                          font=self.controller.text_label_title)
        project_info_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")

        tk.Label(project_info_label, text="Student: ", bg=server_info_label["bg"], fg='cyan',
                 font=self.controller.text_label).grid(row=0, column=0, sticky='w')
        tk.Label(project_info_label, text='Enachi Vasile', bg=server_info_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=20).grid(row=0, column=1, sticky='w')
        tk.Label(project_info_label, text="Grupa: ", bg=server_info_label["bg"], fg='cyan',
                 font=self.controller.text_label).grid(row=1, column=0, sticky='w')
        tk.Label(project_info_label, text='1308B', bg=server_info_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=20).grid(row=1, column=1, sticky='w')
        tk.Label(project_info_label, text="An de studiu: ", bg=server_info_label["bg"], fg='cyan',
                 font=self.controller.text_label).grid(row=2, column=0, sticky='w')
        tk.Label(project_info_label, text='2019-2020', bg=server_info_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=20).grid(row=2, column=1, sticky='w')
        tk.Label(project_info_label, text="Profesor: ", bg=server_info_label["bg"], fg='cyan',
                 font=self.controller.text_label).grid(row=3, column=0, sticky='w')
        tk.Label(project_info_label, text='Nicolae Botezatu', bg=server_info_label["bg"], fg=button_fg,
                 font=self.controller.text_label, width=20).grid(row=3, column=1, sticky='w')


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

        tk.Button(address_server_status_label, text="Save History", width=10, command=self.file_save, bg=button_bg, fg=button_fg, font=self.controller.button_text_font) \
            .grid(row=2, column=0, padx=5, pady=5)
        self.show_packets = tk.IntVar()
        self.show_packets_ch_btn = tk.Checkbutton(address_server_status_label, text="Show Packets", onvalue=1, offvalue=0, command=self.packet_info, variable=self.show_packets, bg=address_server_status_label["bg"], fg='white')
        self.show_packets_ch_btn.grid(row=2, column=1, padx=5, pady=5)

    def release_ip_address(self):
        ip = self.release_ip_combobox.get()
        if ip not in self.controller.dhcp_server.address_pool:
            messagebox.showinfo("IP missing error", "IP not in DHCP Server Address Pool")
            return
        ip_list = [ip for ip, ip_info in self.controller.dhcp_server.address_pool.items() if ip_info['mac'] is not None]
        if ip not in ip_list:
            messagebox.showinfo("IP missing error", "IP is not yet allocated but someone")
            return
        self.controller.dhcp_server.address_pool.update({ip: {'mac': None, 'time': None}})
        self.controller.dhcp_server.debug("Release ip {}".format(ip))
        self.addr_pool_text_widget_fill()
        self.controller.update_frames_address_pool()

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
        self.controller.dhcp_server.old_mac_ip.update({ip: mac_unk})
        self.controller.dhcp_server.debug("Static allocation for mac {}".format(mac_unk))
        self.addr_pool_text_widget_fill()
        self.controller.update_frames_address_pool()

    def file_save(self):
        f = open("dhcp_history.txt", "w")
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
        self.controller.stop_server()
        self.stop_server_button['state'] = tk.DISABLED
        self.other_page.set_pool_address_button['state'] = tk.NORMAL
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
        self.ip_address_pool_text.insert(tk.END, "IP\t\tMAC\t\tLease Time\t\t\tOld MAC\n", 'bold_title')

        for key, value in self.controller.dhcp_server.address_pool.items():
            self.ip_address_pool_text.insert(tk.END, "{}\t\t{}\t\t{}\t\t\t{}\n".format(key, value['mac'], value['time'].strftime("%m/%d/%Y, %H:%M:%S") if value['time'] is not None else "None", self.controller.dhcp_server.old_mac_ip[key]), 'text')