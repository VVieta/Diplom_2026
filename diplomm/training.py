from storage.database import get_connection
from features.feature_extractor import FeatureExtractor
from detection.ml_model import MLDetector

conn = get_connection()

rows = conn.execute(
    """
    SELECT size
    FROM packets
    """
).fetchall()

extractor = FeatureExtractor()

dataset = []

for row in rows:

    features = {
        "packet_count": 1,
        "packets_per_second": 1,
        "avg_packet_size": row[0],
        "max_packet_size": row[0],
        "min_packet_size": row[0],
        "unique_src_ips": 1,
        "proto_tcp_ratio": 1,
        "proto_udp_ratio": 0,
        "proto_icmp_ratio": 0,
        "avg_inter_arrival": 0,
        "std_inter_arrival": 0
    }

    dataset.append(
        extractor.to_vector(features)
    )

model = MLDetector()

model.train(dataset)

print("Model trained")