import socket
import time
import random

SERVER_HOST = '20.0.1.2'
SERVER_PORT = 6653

def simulate_traffic():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        for i in range(10):
            message = f"Packet {i+1}"
            s.sendall(message.encode())
            print(f"[Client] Sent: {message}")
            time.sleep(random.uniform(0.001, 0.1))
        s.close()

if __name__ == "__main__":

    while True:
        simulate_traffic()