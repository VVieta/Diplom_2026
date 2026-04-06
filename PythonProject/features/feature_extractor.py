import collections
import statistics


class FeatureExtractor:
    def extract(self, packets):
        if not packets:
            return self._empty_features()

        timestamps = [p["timestamp"].timestamp() for p in packets]
        sizes = [p["size"] for p in packets]
        src_ips = [p["src_ip"] for p in packets]
        protocols = [p["protocol"] for p in packets]

        window_duration = max(timestamps) - min(timestamps)
        if window_duration == 0:
            window_duration = 1e-6

        features = {}

        features["packet_count"] = len(packets)
        features["packets_per_second"] = len(packets) / window_duration
        features["avg_packet_size"] = statistics.mean(sizes)
        features["max_packet_size"] = max(sizes)
        features["min_packet_size"] = min(sizes)

        features["unique_src_ips"] = len(set(src_ips))

        protocol_counter = collections.Counter(protocols)
        for proto in ["TCP", "UDP", "ICMP"]:
            features[f"proto_{proto.lower()}_ratio"] = (
                protocol_counter.get(proto, 0) / len(packets)
            )

        inter_arrival = self._inter_arrival_times(timestamps)
        if inter_arrival:
            features["avg_inter_arrival"] = statistics.mean(inter_arrival)
            features["std_inter_arrival"] = (
                statistics.stdev(inter_arrival) if len(inter_arrival) > 1 else 0
            )
        else:
            features["avg_inter_arrival"] = 0
            features["std_inter_arrival"] = 0

        return features

    def _inter_arrival_times(self, timestamps):
        timestamps = sorted(timestamps)
        return [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]

    def _empty_features(self):
        return {
            "packet_count": 0,
            "packets_per_second": 0,
            "avg_packet_size": 0,
            "max_packet_size": 0,
            "min_packet_size": 0,
            "unique_src_ips": 0,
            "proto_tcp_ratio": 0,
            "proto_udp_ratio": 0,
            "proto_icmp_ratio": 0,
            "avg_inter_arrival": 0,
            "std_inter_arrival": 0,
        }