#!/usr/bin/env python3
"""
firewall.py — Core firewall engine.

Responsibilities:
  - Rule management (add / delete / persist)
  - ML-based anomaly detection (IsolationForest)
  - SIEM alert forwarding (Native HTTP Logging)
  - Automatic IP banning (with persistence across restarts)
  - iptables integration (Linux; silently skipped on Windows/containers)
  - Packet verdict evaluation
  - Thread-safe stats counters
"""

import json
import os
import subprocess
import time
import threading
import logging
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, wrpcap
from blackwall.ml_detector import MLDetector
from blackwall import os_firewall
from blackwall.threat_intel import get_threat_intel

class Firewall:
    def __init__(self, data_dir: str | None = None):
        self._data_dir = data_dir or os.path.join(os.getcwd(), "data")
        os.makedirs(self._data_dir, exist_ok=True)

        self._rules_file  = os.path.join(self._data_dir, "rules.json")
        self._bans_file   = os.path.join(self._data_dir, "banned_ips.json")
        self._ledger_file = os.path.join(self._data_dir, "ledger.jsonl")
        self._pcaps_dir   = os.path.join(self._data_dir, "pcaps")
        os.makedirs(self._pcaps_dir, exist_ok=True)

        # Basic JSONL logger for ledger
        self.ledger = logging.getLogger("ledger")
        self.ledger.setLevel(logging.INFO)
        fh = logging.FileHandler(self._ledger_file)
        fh.setFormatter(logging.Formatter('%(message)s'))
        if not self.ledger.handlers:
            self.ledger.addHandler(fh)

        # SIEM Webhook
        self.siem_url = os.environ.get("WEBHOOK_URL", "")

        self.rules        : list[dict] = []
        self.banned_ips   : set[str]   = set()
        self._pcap_buffer = defaultdict(lambda: deque(maxlen=100))
        self.ml_detector  = MLDetector()
        self._stats       = {"total": 0, "allow": 0, "drop": 0, "banned": 0}
        self._lock        = threading.Lock()
        self._next_id     = 0

        self._load_bans()
        self.load_rules()

    def log_event(self, event: dict) -> None:
        event["timestamp"] = time.time()
        self.ledger.info(json.dumps(event))

    def _load_bans(self) -> None:
        if not os.path.exists(self._bans_file): return
        try:
            with open(self._bans_file, "r") as f:
                self.banned_ips = set(json.load(f))
            with self._lock: self._stats["banned"] = len(self.banned_ips)
        except Exception:
            self.banned_ips = set()

    def _save_bans(self) -> None:
        tmp = self._bans_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(sorted(self.banned_ips), f, indent=2)
        os.replace(tmp, self._bans_file)

    def load_rules(self) -> None:
        if not os.path.exists(self._rules_file): return
        try:
            with open(self._rules_file, "r") as f: data = json.load(f)
            for r in data:
                self.add_rule(r["action"], r.get("ip"), r.get("port"), r.get("proto"), r.get("comment", ""), False, False)
        except Exception:
            self.rules, self._next_id = [], 0

    def save_rules(self) -> None:
        tmp = self._rules_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.rules, f, indent=2)
        os.replace(tmp, self._rules_file)

    def add_rule(self, action, ip=None, port=None, proto=None, comment="", log=True, apply_iptables=True, pcap_file=None) -> dict:
        with self._lock:
            rule_id = self._next_id
            self._next_id += 1
        rule = {
            "id": rule_id, "action": action.upper(), "ip": ip or None,
            "port": int(port) if port is not None else None,
            "proto": proto.upper() if proto else None, "comment": comment,
            "pcap_file": pcap_file, "created": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
        with self._lock:
            self.rules.append(rule)
        if log: self.log_event({"type": "rule_add", "rule": rule})
        if apply_iptables: os_firewall.apply_rule(rule, add=True)
        self.save_rules()
        return rule

    def delete_rule(self, rule_id: int) -> bool:
        removed_rule = None
        with self._lock:
            for r in self.rules:
                if r.get("id") == rule_id:
                    removed_rule = r
                    break
            if removed_rule:
                self.rules = [r for r in self.rules if r.get("id") != rule_id]
        if removed_rule:
            os_firewall.apply_rule(removed_rule, add=False)
            self.log_event({"type": "rule_delete", "rule_id": rule_id})
            self.save_rules()
            return True
        return False

    def get_rules(self) -> list[dict]:
        with self._lock: return list(self.rules)

    def _ban_ip(self, ip: str) -> None:
        if ip in self.banned_ips: return
        self.banned_ips.add(ip)
        with self._lock: self._stats["banned"] += 1
        self._save_bans()
        
        pcap_path = None
        if self._pcap_buffer[ip]:
            pcap_path = os.path.join(self._pcaps_dir, f"ban_{ip.replace('.', '_')}_{int(time.time())}.pcap")
            try: wrpcap(pcap_path, list(self._pcap_buffer[ip]))
            except: pcap_path = None
            del self._pcap_buffer[ip]

        self.add_rule("DROP", ip=ip, comment=f"auto-ban: ML anomaly detected at {time.strftime('%H:%M:%S')}", pcap_file=pcap_path)
        print(f"[fw] AUTO-BAN {ip} (ML anomaly)")

        if self.siem_url:
            threading.Thread(target=self._send_siem, args=({"type": "auto_ban", "ip": ip, "reason": "ML anomaly"},), daemon=True).start()

    def _send_siem(self, event):
        import urllib.request, json
        try:
            payload_str = json.dumps(event, indent=2)
            if "discord.com" in self.siem_url:
                data = json.dumps({"content": f"```json\n{payload_str}\n```"}).encode()
            elif "slack.com" in self.siem_url:
                data = json.dumps({"text": f"```json\n{payload_str}\n```"}).encode()
            else:
                data = json.dumps({"text": json.dumps(event)}).encode()

            req = urllib.request.Request(self.siem_url, data, {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass

    def unban_ip(self, ip: str) -> bool:
        if ip not in self.banned_ips: return False
        self.banned_ips.discard(ip)
        self.ml_detector.reset(ip)
        with self._lock: self._stats["banned"] = max(0, self._stats["banned"] - 1)
        with self._lock:
            to_remove = [r for r in self.rules if r.get("ip") == ip and "auto-ban" in r.get("comment", "")]
        for r in to_remove: self.delete_rule(r["id"])
        self._save_bans()
        return True

    def check_packet(self, pkt) -> str:
        ip_src, dport, proto = None, None, None
        if IP in pkt: ip_src = pkt[IP].src
        if TCP in pkt: dport, proto = pkt[TCP].dport, "TCP"
        elif UDP in pkt: dport, proto = pkt[UDP].dport, "UDP"

        if ip_src:
            self._pcap_buffer[ip_src].append(pkt)
            # Minimal threat intel
            get_threat_intel(ip_src)
            self.ml_detector.record(ip_src, len(pkt), dport, proto)
            if self.ml_detector.check_ip(ip_src): self._ban_ip(ip_src)

        verdict = "DROP" if ip_src in self.banned_ips else self._match_rules(ip_src, dport, proto)

        with self._lock:
            self._stats["total"] += 1
            if verdict == "ALLOW": self._stats["allow"] += 1
            else: self._stats["drop"] += 1

        self.log_event({"type": "packet_log", "src": ip_src, "dport": dport, "proto": proto, "verdict": verdict})
        return verdict

    def _match_rules(self, ip_src, dport, proto) -> str:
        with self._lock: rules = list(self.rules)
        for rule in rules:
            if rule.get("ip") and rule["ip"] != ip_src: continue
            if rule.get("port") and rule["port"] != dport: continue
            if rule.get("proto") and rule["proto"] != proto: continue
            return rule["action"]
        return "ALLOW"

    def get_stats(self) -> dict:
        with self._lock: return dict(self._stats)
