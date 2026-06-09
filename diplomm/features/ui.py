import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog

import threading
import time

from storage.database import save_packet
from attack_tests import ddos
from attack_tests import port_scan
from attack_tests import brute_force

from utils.config import load_config
from core.engine import IDSEngine

from capture.packet_sniffer import start_sniffing

class IDSInterface:

    def __init__(self):

        self.root = tk.Tk()

        self.root.title("IDS Demo Interface")
        self.root.geometry("900x550")

        # =================================================
        # ФЛАГ РАБОТЫ SNIFFER
        # =================================================
        self.running_flag = {
            "running": False
        }

        self.sniffer_thread = None

        # =================================================
        # ФЛАГ РАБОТЫ АТАК
        # =================================================
        self.attack_flag = {
            "running": False
        }

        self.attack_thread = None

        # =================================================
        # ОГРАНИЧЕНИЕ СКОРОСТИ ВЫВОДА
        # =================================================
        self.last_packet_time = 0

        # обычный трафик → 1 пакет в секунду
        self.normal_interval = 1.0

        # во время атаки → быстрее
        self.attack_interval = 0.05

        self.display_interval = self.normal_interval

        config = load_config()

        self.engine = IDSEngine(config)

        self.engine.interface = self

        self.engine_thread = None

        # =================================================
        # ОКНО ОТЧЁТА
        # =================================================
        self.report_area = scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            width=100,
            height=22
        )

        self.report_area.pack(pady=10)

        self.report_area.tag_config(
            "HIGH",
            foreground="red"
        )

        self.report_area.tag_config(
            "MEDIUM",
            foreground="orange"
        )

        self.report_area.tag_config(
            "LOW",
            foreground="green"
        )

        # =================================================
        # START / STOP
        # =================================================
        center_frame = tk.Frame(self.root)
        center_frame.pack(pady=10)

        self.start_button = tk.Button(
            center_frame,
            text="Start",
            width=12,
            command=self.start_clicked
        )

        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = tk.Button(
            center_frame,
            text="Stop",
            width=12,
            command=self.stop_clicked
        )

        self.stop_button.grid(row=0, column=1, padx=10)

        # =================================================
        # ТЕКСТ ВЫБРАННОЙ АТАКИ
        # =================================================
        self.selected_attack_label = tk.Label(
            self.root,
            text="Selected attack: None",
            font=("Arial", 11)
        )

        self.selected_attack_label.pack(pady=5)

        # =================================================
        # SAVE / CLEAR / RUN ATTACK
        # =================================================
        utility_frame = tk.Frame(self.root)
        utility_frame.pack(pady=5)

        self.save_button = tk.Button(
            utility_frame,
            text="Save",
            width=12,
            command=self.save_log
        )

        self.save_button.grid(row=0, column=0, padx=10)

        self.clear_button = tk.Button(
            utility_frame,
            text="Clear",
            width=12,
            command=self.clear_log
        )

        self.clear_button.grid(row=0, column=1, padx=10)

        self.attack_button = tk.Button(
            utility_frame,
            text="Run Attack",
            width=15,
            command=self.run_selected_attack
        )

        self.attack_button.grid(row=0, column=2, padx=10)

        # =================================================
        # НИЖНИЙ БЛОК
        # =================================================
        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, pady=20)

        # =================================================
        # СПИСОК АТАК
        # =================================================
        self.attack_options = [
            "None",
            "DDoS Attack",
            "Port Scan",
            "Brute Force"
        ]

        self.attack_var = tk.StringVar()

        self.attack_var.set(self.attack_options[0])

        # =================================================
        # COMBOBOX
        # =================================================
        self.attack_menu = ttk.Combobox(
            bottom_frame,
            textvariable=self.attack_var,
            values=self.attack_options,
            state="readonly",
            width=25
        )

        self.attack_menu.pack()

        self.attack_menu.bind(
            "<<ComboboxSelected>>",
            self.attack_selected
        )

    # =====================================================
    # ЛОГ
    # =====================================================
    def log(self, text):

        self.report_area.insert(tk.END, text + "\n")
        self.report_area.see(tk.END)

    # =====================================================
    # ALERT
    # =====================================================
    def alert(self, text, level="HIGH"):

        if level == "HIGH":
            prefix = "[!!! ALERT !!!]"
        elif level == "MEDIUM":
            prefix = "[WARNING]"
        else:
            prefix = "[INFO]"

        self.report_area.insert(
            tk.END,
            f"{prefix} {text}\n",
            level
        )

        self.report_area.see(tk.END)
    # =====================================================
    # СОХРАНЕНИЕ ЛОГА
    # =====================================================
    def save_log(self):

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )

        if not file_path:
            return

        log_text = self.report_area.get("1.0", tk.END)

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(log_text)

        self.log("[SYSTEM] Log saved successfully")

    # =====================================================
    # ОЧИСТКА ЛОГА
    # =====================================================
    def clear_log(self):

        self.report_area.delete("1.0", tk.END)

    # =====================================================
    # ОБРАБОТКА ПАКЕТА
    # =====================================================
    def handle_packet(self, packet):

        now = time.time()

        save_packet(packet)

        self.engine.handle_packet(packet)
        # ==========================================
        # LIMIT OUTPUT SPEED
        # ==========================================
        if now - self.last_packet_time < self.display_interval:
            return

        self.last_packet_time = now

        log_message = (
            f"[{packet['timestamp'].strftime('%H:%M:%S')}] "
            f"{packet['protocol']} | "
            f"{packet['src_ip']}:{packet['src_port']} -> "
            f"{packet['dst_ip']}:{packet['dst_port']} | "
            f"SIZE: {packet['size']}"
        )

        self.root.after(0, lambda: self.log(log_message))

    # =====================================================
    # START
    # =====================================================
    def start_clicked(self):

        if self.running_flag["running"]:
            self.log("[SYSTEM] Sniffer already running")
            return

        self.running_flag["running"] = True
        self.engine.running = True

        self.engine_thread = threading.Thread(
            target=self.engine.start,
            daemon=True
        )

        self.engine_thread.start()
        self.log("[SYSTEM] Starting packet sniffer...")

        self.sniffer_thread = threading.Thread(
            target=start_sniffing,
            args=(self.handle_packet, self.running_flag),
            daemon=True
        )

        self.sniffer_thread.start()

    # =====================================================
    # STOP
    # =====================================================
    def stop_clicked(self):

        if not self.running_flag["running"]:
            self.log("[SYSTEM] Sniffer already stopped")
            return

        self.running_flag["running"] = False
        self.attack_flag["running"] = False
        self.engine.stop()
        # вернуть обычную скорость
        self.display_interval = self.normal_interval

        self.log("[SYSTEM] Packet sniffer stopped")

    # =====================================================
    # ВЫБОР АТАКИ
    # =====================================================
    def attack_selected(self, event):

        selected = self.attack_var.get()

        self.selected_attack_label.config(
            text=f"Selected attack: {selected}"
        )

        self.log(f"[UI] Selected attack: {selected}")

    # =====================================================
    # ЗАПУСК АТАКИ
    # =====================================================
    def run_selected_attack(self):

        selected = self.attack_var.get()

        # =============================================
        # ОСТАНОВКА ТЕКУЩЕЙ АТАКИ
        # =============================================
        self.attack_flag["running"] = False

        # вернуть обычную скорость
        self.display_interval = self.normal_interval

        if selected == "None":

            self.log("[ATTACK] Attack simulation stopped")
            return

        self.attack_flag["running"] = True

        # ускоряем вывод во время атаки
        self.display_interval = self.attack_interval

        self.log(f"[ATTACK] Running: {selected}")

        # =============================================
        # DDOS
        # =============================================
        if selected == "DDoS Attack":

            self.attack_thread = threading.Thread(
                target=ddos.run,
                args=(self.attack_flag,),
                daemon=True
            )

        # =============================================
        # PORT SCAN
        # =============================================
        elif selected == "Port Scan":

            self.attack_thread = threading.Thread(
                target=port_scan.run,
                args=(self.attack_flag,),
                daemon=True
            )

        # =============================================
        # BRUTE FORCE
        # =============================================
        elif selected == "Brute Force":

            self.attack_thread = threading.Thread(
                target=brute_force.run,
                args=(self.attack_flag,),
                daemon=True
            )

        # =============================================
        self.attack_thread.start()



    # =====================================================
    # RUN
    # =====================================================
    def run(self):

        self.root.mainloop()