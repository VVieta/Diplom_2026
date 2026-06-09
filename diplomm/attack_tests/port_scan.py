import socket
import time


import socket

TARGET = socket.gethostbyname(
    socket.gethostname()
)


def run(attack_flag):

    print("[ATTACK] Port scan started")

    while attack_flag["running"]:

        for port in range(20, 200):

            if not attack_flag["running"]:
                break

            try:

                sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                sock.settimeout(0.05)

                sock.connect_ex((TARGET, port))

                sock.close()

            except Exception:
                pass

            time.sleep(0.01)

    print("[ATTACK] Port scan stopped")