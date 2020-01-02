import tkinter as tk
from abc import abstractmethod


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

    @staticmethod
    def is_number(number, min_range=0, max_range=1_000_000_000_000, zero_permited=False):
        import re
        try:
            number_temp = float(number)
            if zero_permited and number_temp == 0:
                return True
            if number_temp <= min_range or number_temp >= max_range:
                return False
        except ValueError:
            return False
        return bool(re.match(r"[\d]+(.\d)?[\d]*", number))