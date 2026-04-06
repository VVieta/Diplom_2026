from core.engine import IDSEngine
from utils.config import load_config
from utils.logger import setup_logger


def main():
    config = load_config()
    setup_logger()

    engine = IDSEngine(config)
    engine.start()


if __name__ == "__main__":
    main()