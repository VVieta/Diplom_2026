

import time
from collections import deque


class FlowManager:

    def __init__(self, timeout=30):

        self.flows = {}
        self.timeout = timeout

    # =====================================================
    # FLOW KEY
    # =====================================================
    def create_flow_key(self, packet):

        src = (packet["src_ip"], packet["src_port"])
        dst = (packet["dst_ip"], packet["dst_port"])

        ordered = sorted([src, dst])

        return (
            ordered[0],
            ordered[1],
            packet["protocol"]
        )

    # =====================================================
    # ADD PACKET
    # =====================================================
    def add_packet(self, packet):

        key = self.create_flow_key(packet)

        now = time.time()

        # =================================================
        # NEW FLOW
        # =================================================
        if key not in self.flows:

            self.flows[key] = {

                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],

                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],

                "protocol": packet["protocol"],

                "start_time": now,
                "last_seen": now,

                "packet_count": 0,
                "total_bytes": 0,

                # последние 50 пакетов
                "packets": deque(maxlen=50)
            }

        flow = self.flows[key]

        flow["last_seen"] = now

        flow["packet_count"] += 1
        flow["total_bytes"] += packet["size"]

        flow["packets"].append(packet)

    # =====================================================
    # GET FLOWS
    # =====================================================
    def get_flows(self):

        return self.flows

    # =====================================================
    # REMOVE OLD FLOWS
    # =====================================================
    def cleanup_old_flows(self):

        now = time.time()

        expired = []

        for key, flow in self.flows.items():

            if now - flow["last_seen"] > self.timeout:
                expired.append(key)

        return expired

    # =====================================================
    # DELETE FLOW
    # =====================================================
    def remove_flow(self, key):

        if key in self.flows:
            del self.flows[key]

    # =====================================================
    # FLOW STATISTICS
    # =====================================================
    def get_flow_statistics(self):

        stats = []

        for key, flow in self.flows.items():

            duration = (
                flow["last_seen"] -
                flow["start_time"]
            )

            if duration <= 0:
                duration = 0.001

            stats.append({

                "flow_key": key,

                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],

                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],

                "protocol": flow["protocol"],

                "packet_count": flow["packet_count"],

                "total_bytes": flow["total_bytes"],

                "duration": duration,

                "packets_per_second":
                    flow["packet_count"] / duration
            })

        return stats