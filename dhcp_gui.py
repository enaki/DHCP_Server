import tkinter as tk
import logging as log


class DHCP_Server_GUI(tk.Frame):
    def __init__(self, master=None):
        self.w = 800
        self.h = 500
        self.master = master
        tk.Frame.__init__(self, master, bg="black")
        self.init_window()

    def init_window(self):
        self.master.title("DHCP Server")
        self.pack(fill=tk.BOTH, expand=1)
        quit_button = tk.Button(self, text="Close", command=self.gui_exit, height=2, width=10)
        # log.info("width = {}    height = {}".format(self.master.winfo_width(), self.master.winfo_height()))
        quit_button.place(x=self.w - 100, y=self.h - 80)

    @staticmethod
    def gui_exit():
        log.info('Stopping Server')
        exit()
