import time
import threading

from core.window_manager import WindowManager
from capture.packet_sniffer import start_sniffing
from features.feature_extractor import FeatureExtractor
from detection.statistical import StatisticalDetector
from utils.logger import log_anomaly


class IDSEngine:
    def __init__(self, config):
        self.window_manager = WindowManager(config["window_size"])
        self.extractor = FeatureExtractor()
        self.detector = StatisticalDetector()
        self.running = True

    def start(self):
        print("[ENGINE] Started")

        sniff_thread = threading.Thread(
            target=start_sniffing,
            args=(None, self.handle_packet),
            daemon=True
        )
        sniff_thread.start()

        while self.running:
            self.window_manager.check_window(self.process_window)
            time.sleep(0.5)

    def handle_packet(self, packet):
        self.window_manager.add_packet(packet)

    def process_window(self, packets):
        if not packets:
            return

        features = self.extractor.extract(packets)
        score = self.detector.detect(features)

        if score > 0.7:
            log_anomaly(features)

        print(f"[WINDOW] packets: {len(packets)}")

    def stop(self):
        self.running = False