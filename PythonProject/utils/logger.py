import logging
import os

LOG_FILE = "anomalies.txt"


def setup_logger():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
    )

    print("[LOGGER] File logging initialized")


def log_anomaly(features):
    logging.info("=== ANOMALY DETECTED ===")
    for key, value in features.items():
        logging.info(f"{key}: {value}")
    logging.info("------------------------")