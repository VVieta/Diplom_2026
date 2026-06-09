import socket
import time

TARGET_IP = socket.gethostbyname(
    socket.gethostname()
)

TARGET_PORT = 9999


def run(attack_flag):

    print("[ATTACK] DDoS simulation started")

    while attack_flag["running"]:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            sock.sendto(
                b"DDOS_PACKET",
                (TARGET_IP, TARGET_PORT)
            )

            sock.close()

        except Exception as e:
            print(e)

        time.sleep(0.01)

    print("[ATTACK] DDoS simulation stopped")