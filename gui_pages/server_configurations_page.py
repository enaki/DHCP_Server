import socket
import tkinter as tk
from tkinter import ttk, messagebox

from gui_pages.server_basic_page import ServerPage
from dhcp_server import DHCP_Server


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
        self.mask_entry = ttk.Combobox(address_pool_label, state='readonly', width=27, values=["/{}".format(str(x)) for x in range(16, 31)])
        self.mask_entry.grid(row=1, column=1, padx=5, pady=5)

        self.ip_address_entry.insert(0, '10.1.0.127')
        self.mask_entry.current(13)
        self.set_pool_address_button = tk.Button(address_pool_label, text='Set Pool Address', command=self.set_pool_address, bg=button_bg, fg=button_fg, font=self.controller.button_text_font)
        self.set_pool_address_button.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(address_pool_label, text='View Pool Address', command=self.addr_pool_text_widget_fill, bg=button_bg,
                  fg=button_fg, font=self.controller.button_text_font).grid(row=2, column=0, padx=5, pady=5)

        address_pool_viewer_label = tk.LabelFrame(address_pool_frame, text="Address Pool Viewer", bg=label_bg, fg='yellow', font=self.controller.text_label_title)
        address_pool_viewer_label.grid(row=1, column=0, padx=10, pady=10, sticky='w')

        self.ip_address_pool_text = tk.Text(address_pool_viewer_label, height=25, width=50, bg="#101010", fg='light green')
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

            self.controller.update_frames_address_pool()
            self.addr_pool_text_widget_fill()
            if self.other_page.server_name_label_var.get() != "unknown" and self.other_page.lease_time_label_var != "unknown":
                self.other_page.start_server_button['state'] = tk.NORMAL
        except socket.error:
            messagebox.showinfo("IP Format error", "IP Format: x.x.x.x where x = 0-255")
        except ValueError:
            messagebox.showinfo("Mask Format error", "Mask Format: x or \\x, where x = 1-32")
        except OSError:
            messagebox.showinfo("IP Format error", "IP Format: x.x.x.x where x = 0-255")

    def addr_pool_text_widget_fill(self):
        mask = self.mask_entry.get()
        ip = self.ip_address_entry.get()
        self.controller.dhcp_server.debug("View pool address")
        try:
            mask_result = self._check_pool_is_correct(ip, mask)
        except OSError:
            messagebox.showinfo("IP Format error", "IP Format: x.x.x.x where x = 0-255")
            return
        starting_ip = self._get_ip_network_of_ipv4(ip, mask_result)
        address_pool, address_pool_broadcast = DHCP_Server.calculate_address_pool(starting_ip, mask_result)

        self.ip_address_pool_text.delete(1.0, tk.END)
        self.ip_address_pool_text.insert(tk.END, "Net Address : {}\n".format(starting_ip))
        self.ip_address_pool_text.insert(tk.END, "Broadcast Address : {}\n".format(address_pool_broadcast))
        for key, value in address_pool.items():
            self.ip_address_pool_text.insert(tk.END, key + '\n')

    def set_server_name(self):
        server_name = self.server_name_entry.get()
        if len(server_name) > 64:
            messagebox.showinfo("Server Name Error", "Server Name string length should be lower than 64")
            return
        self.controller.dhcp_server.debug("Set Server Name '{}'".format(server_name))
        self.other_page.server_name_label_var.set(server_name)
        self.controller.dhcp_server.set_server_name(server_name)
        if self.other_page.mask_label_var.get() != "unknown" and self.other_page.lease_time_label_var.get() != "unknown":
            self.other_page.start_server_button['state'] = tk.NORMAL

    def set_server_lease_time(self):
        lease_time = self.lease_time_entry.get()
        if not lease_time.isdigit() or not self.is_number(lease_time):
            messagebox.showinfo("Lease Time Error", "Lease Time should be a valid number")
            return
        self.controller.dhcp_server.debug("Set Lease Time {}".format(lease_time))
        import time
        self.other_page.lease_time_label_var.set("{} days {}".format(int(lease_time) // 86400, time.strftime('%H:%M:%S', time.gmtime(int(lease_time)))))
        self.controller.dhcp_server.set_server_lease_time(int(lease_time))
        if self.other_page.server_name_label_var.get() != "unknown" and self.other_page.mask_label_var.get() != "unknown":
            self.other_page.start_server_button['state'] = tk.NORMAL