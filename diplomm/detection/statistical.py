import socket

TARGET = socket.gethostbyname(
    socket.gethostname()
)


class StatisticalDetector:

    def __init__(self):

        self.pps_threshold = 150
        self.flow_pps_threshold = 80
        self.port_scan_threshold = 20
        self.unique_ip_threshold = 10

    # =====================================================
    # MAIN DETECTION
    # =====================================================
    def detect(self, features, flow_stats):

        score = 0.0
        alerts = []

        # =================================================
        # HIGH PACKETS PER SECOND
        # =================================================
        if features["packets_per_second"] > self.pps_threshold:

            score += 0.4

            alerts.append(
                "High packets per second detected"
            )

        # =================================================
        # MANY SOURCE IPS
        # =================================================
        if features["unique_src_ips"] > self.unique_ip_threshold:

            score += 0.3

            alerts.append(
                "Large number of source IPs"
            )

        # =================================================
        # FLOW ANALYSIS
        # =================================================
        suspicious_flows = 0

        ports_by_ip = {}

        for flow in flow_stats:

            # Flood-like activity
            if flow["packets_per_second"] > self.flow_pps_threshold:
                suspicious_flows += 1

            # Port scan preparation
            ip = flow["src_ip"]

            if ip not in ports_by_ip:
                ports_by_ip[ip] = set()

            if flow["dst_port"] is not None:
                ports_by_ip[ip].add(
                    flow["dst_port"]
                )

        # =================================================
        # PORT SCAN DETECTION
        # =================================================
        for ip, ports in ports_by_ip.items():

            if len(ports) > self.port_scan_threshold:

                score += 0.5

                alerts.append(
                    f"Port scan detected from {ip}"
                )

        # =================================================
        # FLOW FLOODING
        # =================================================
        if suspicious_flows > 5:

            score += 0.4

            alerts.append(
                "Possible flooding activity"
            )

        return {
            "score": min(score, 1.0),
            "alerts": alerts
        }