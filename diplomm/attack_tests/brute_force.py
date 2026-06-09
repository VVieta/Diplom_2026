import socket
import time


import socket

TARGET = socket.gethostbyname(
    socket.gethostname()
)


def run(attack_flag):

    print("[ATTACK] Brute force simulation started")

    PORT = 3389

    while attack_flag["running"]:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(0.1)

            sock.connect_ex((TARGET, PORT))

            sock.close()

        except Exception:
            pass

        time.sleep(0.05)

    print("[ATTACK] Brute force simulation stopped")