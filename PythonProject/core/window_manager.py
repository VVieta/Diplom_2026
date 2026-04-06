import time


class WindowManager:
    def __init__(self, window_size):
        self.window_size = window_size
        self.packets = []
        self.window_start = time.time()

    def add_packet(self, packet):
        self.packets.append(packet)

    def check_window(self, callback):
        now = time.time()
        if now - self.window_start >= self.window_size:
            callback(self.packets.copy())
            self.packets.clear()
            self.window_start = now