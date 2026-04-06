class StatisticalDetector:
    def detect(self, features):
        if features["packets_per_second"] > 20:
            return 1.0
        return 0.0