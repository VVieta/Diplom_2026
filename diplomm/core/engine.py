# core/engine.py

import time
import threading

from core.window_manager import WindowManager
from core.flow_manager import FlowManager

from capture.packet_sniffer import start_sniffing

from features.feature_extractor import FeatureExtractor

from detection.statistical import StatisticalDetector

from storage.database import save_flow
from storage.database import save_alert

from utils.logger import log_anomaly


class IDSEngine:

    def __init__(self, config):

        self.window_manager = WindowManager(
            config["window_size"]
        )

        self.flow_manager = FlowManager(
            config["flow_timeout"]
        )

        self.extractor = FeatureExtractor()

        self.detector = StatisticalDetector()

        self.interface = config["interface"]


        self.running = True

        self.running_flag = {
            "running": True
        }

    # =====================================================
    # START
    # =====================================================
    def start(self):

        print("[ENGINE] Started")

        while self.running:
            self.window_manager.check_window(
                self.process_window
            )

            self.cleanup_flows()

            time.sleep(0.5)

    # =====================================================

    def handle_packet(self, packet):

        self.window_manager.add_packet(packet)

        self.flow_manager.add_packet(packet)

    # =====================================================


    def process_window(self, packets):

        if not packets:
            return

        features = self.extractor.extract(
            packets
        )

        flow_stats = (
            self.flow_manager.get_flow_statistics()
        )

        result = self.detector.detect(
            features,
            flow_stats
        )

        score = result["score"]
        alerts = result["alerts"]

        final_score = score



        # =================================================
        # alert
        if final_score > 0.7:

            for alert in alerts:

                level = "LOW"

                if score > 0.8:
                    level = "HIGH"
                elif score > 0.5:
                    level = "MEDIUM"

                self.interface.alert(
                    alert,
                    level
                )

                save_alert(
                    "NETWORK_ANOMALY",
                    "HIGH",
                    alert,
                    score
                )

            log_anomaly(features)

        print(
            f"[WINDOW] packets: {len(packets)} | "
            f"score: {score}"
        )

    # =====================================================

    def cleanup_flows(self):

        expired = (
            self.flow_manager.cleanup_old_flows()
        )

        flows = self.flow_manager.get_flows()

        for key in expired:

            if key not in flows:
                continue

            flow = flows[key]

            duration = (
                flow["last_seen"] -
                flow["start_time"]
            )

            if duration <= 0:
                duration = 0.001

            save_flow({

                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],

                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],

                "protocol": flow["protocol"],

                "packet_count":
                    flow["packet_count"],

                "total_bytes":
                    flow["total_bytes"],

                "duration":
                    duration
            })

            self.flow_manager.remove_flow(key)

    # =====================================================

    def stop(self):

        self.running = False

        self.running_flag["running"] = False

        print("[ENGINE] Stopped")