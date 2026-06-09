from storage.database import init_db
from features.ui import IDSInterface
from core.engine import IDSEngine
from utils.config import load_config

import threading


def main():

    init_db()

    app = IDSInterface()

    config = load_config()
    config["interface"] = app

    engine = IDSEngine(config)

    threading.Thread(
        target=engine.start,
        daemon=True
    ).start()

    app.run()


if __name__ == "__main__":
    main()