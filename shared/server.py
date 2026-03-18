import socket
import threading
import time

HOST = '0.0.0.0'
PORT = 6653

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[{addr}] Received: {data.decode()}")
    print(f"[-] Connection closed from {addr}")

def monitor_load(load):
    while True:
        print(f"[load_monitor] Current load: {load[0]}")
        time.sleep(5)

def start_server():
    load = [0]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server listening on {HOST}:{PORT}")
        monitor_thread = threading.Thread(target=monitor_load, args=(load,), daemon=True)
        monitor_thread.start()
        while True:
            conn, addr = s.accept()
            load[0] += 1
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    start_server()