#!/usr/bin/env python3
"""
firewall.py — Core firewall engine.

Responsibilities:
  - Rule management (add / delete / persist)
  - ML-based anomaly detection (IsolationForest)
  - SIEM alert forwarding (Splunk HEC / Wazuh)
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
from collections import defaultdict
from scapy.all import IP, TCP, UDP
from blackwall.blockchain import Blockchain
from blackwall.ml_detector import MLDetector
from blackwall.siem_forwarder import SIEMForwarder
from blackwall import os_firewall
from blackwall.threat_intel import ThreatIntel


class Firewall:
    def __init__(self, ledger: Blockchain, data_dir: str | None = None):
        # Resolve data directory (location-agnostic)
        self._data_dir = data_dir or os.path.join(os.getcwd(), "data")
        os.makedirs(self._data_dir, exist_ok=True)

        self._rules_file = os.path.join(self._data_dir, "rules.json")
        self._bans_file  = os.path.join(self._data_dir, "banned_ips.json")

        self.ledger       = ledger
        self.rules        : list[dict] = []
        self.banned_ips   : set[str]   = set()
        self.ml_detector  = MLDetector()
        self.siem         = SIEMForwarder()
        self.threat_intel = ThreatIntel(data_dir=self._data_dir)
        self._stats       = {"total": 0, "allow": 0, "drop": 0, "banned": 0}
        self._lock        = threading.Lock()
        self._next_id     = 0   # monotonic rule ID counter (avoids collision after delete)

        self._load_bans()
        self.load_rules()

    # ------------------------------------------------------------------
    # Persistence — rules
    # ------------------------------------------------------------------

    def load_rules(self) -> None:
        """Load rules from disk without triggering iptables or ledger writes."""
        if not os.path.exists(self._rules_file):
            return
        try:
            with open(self._rules_file, "r") as f:
                data = json.load(f)
            for r in data:
                self.add_rule(
                    action        = r["action"],
                    ip            = r.get("ip"),
                    port          = r.get("port"),
                    proto         = r.get("proto"),
                    comment       = r.get("comment", ""),
                    log           = False,
                    apply_iptables= False,
                )
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"[fw] rules file corrupted ({exc}) — starting fresh.")
            self.rules    = []
            self._next_id = 0

    def save_rules(self) -> None:
        """Persist the current rule list atomically."""
        tmp = self._rules_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.rules, f, indent=2)
        os.replace(tmp, self._rules_file)

    # ------------------------------------------------------------------
    # Persistence — banned IPs
    # ------------------------------------------------------------------

    def _load_bans(self) -> None:
        """Restore banned IPs from disk so bans survive restarts."""
        if not os.path.exists(self._bans_file):
            return
        try:
            with open(self._bans_file, "r") as f:
                bans = json.load(f)
            self.banned_ips = set(bans)
            with self._lock:
                self._stats["banned"] = len(self.banned_ips)
        except (json.JSONDecodeError, TypeError):
            self.banned_ips = set()

    def _save_bans(self) -> None:
        tmp = self._bans_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(sorted(self.banned_ips), f, indent=2)
        os.replace(tmp, self._bans_file)

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(
        self,
        action        : str,
        ip            : str | None = None,
        port          : int | None = None,
        proto         : str | None = None,
        comment       : str        = "",
        log           : bool       = True,
        apply_iptables: bool       = True,
    ) -> dict:
        """Add a firewall rule. Returns the created rule dict."""
        with self._lock:
            rule_id       = self._next_id
            self._next_id += 1

        rule = {
            "id":      rule_id,
            "action":  action.upper(),
            "ip":      ip or None,
            "port":    int(port) if port is not None else None,
            "proto":   proto.upper() if proto else None,
            "comment": comment,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

        with self._lock:
            self.rules.append(rule)

        if log:
            self.ledger.add_block({"type": "rule_add", "rule": rule})
        if apply_iptables:
            os_firewall.apply_rule(rule, add=True)
        self.save_rules()
        return rule

    def delete_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID. Returns True on success."""
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
            self.ledger.add_block({"type": "rule_delete", "rule_id": rule_id})
            self.save_rules()
            return True
        return False

    def get_rules(self) -> list[dict]:
        with self._lock:
            return list(self.rules)

    # ------------------------------------------------------------------
    # Auto-ban
    # ------------------------------------------------------------------

    def _ban_ip(self, ip: str) -> None:
        """Auto-ban an IP flagged as anomalous by the ML detector."""
        if ip in self.banned_ips:
            return
        self.banned_ips.add(ip)
        with self._lock:
            self._stats["banned"] += 1
        self._save_bans()
        self.add_rule(
            action  = "DROP",
            ip      = ip,
            comment = f"auto-ban: ML anomaly detected at {time.strftime('%H:%M:%S')}",
        )
        print(f"[fw] AUTO-BAN {ip} (ML anomaly)")

        # Forward ban event to SIEM
        self.siem.forward({
            "type":   "auto_ban",
            "ip":     ip,
            "reason": "ML anomaly detection (IsolationForest)",
        })

    def unban_ip(self, ip: str) -> bool:
        """
        Remove an IP from the ban list, reset its ML detector state,
        and delete the corresponding auto-ban DROP rule.
        Returns True if the IP was actually banned.
        """
        if ip not in self.banned_ips:
            return False

        self.banned_ips.discard(ip)
        self.ml_detector.reset(ip)
        with self._lock:
            self._stats["banned"] = max(0, self._stats["banned"] - 1)

        # Remove the auto-ban rule(s) for this IP
        with self._lock:
            to_remove = [
                r for r in self.rules
                if r.get("ip") == ip and "auto-ban" in r.get("comment", "")
            ]
        for r in to_remove:
            self.delete_rule(r["id"])

        self._save_bans()
        return True

    # ------------------------------------------------------------------
    # Packet inspection
    # ------------------------------------------------------------------

    def check_packet(self, pkt) -> str:
        """Evaluate a Scapy packet. Returns 'ALLOW' or 'DROP'."""
        ip_src, dport, proto = None, None, None
        pkt_bytes = len(pkt)

        if IP in pkt:
            ip_src = pkt[IP].src
        if TCP in pkt:
            dport, proto = pkt[TCP].dport, "TCP"
        elif UDP in pkt:
            dport, proto = pkt[UDP].dport, "UDP"

        # ML anomaly detection & Threat Intel async enrichment
        if ip_src:
            self.threat_intel.query_async(ip_src)
            self.ml_detector.record(ip_src, pkt_bytes, dport, proto)
            if self.ml_detector.check_ip(ip_src):
                self._ban_ip(ip_src)

        verdict = "DROP" if ip_src in self.banned_ips else self._match_rules(ip_src, dport, proto)

        with self._lock:
            self._stats["total"] += 1
            if verdict == "ALLOW":
                self._stats["allow"] += 1
            else:
                self._stats["drop"] += 1

        self.ledger.add_block({
            "type":    "packet_log",
            "src":     ip_src,
            "dport":   dport,
            "proto":   proto,
            "verdict": verdict,
        })

        # Forward DROP events to SIEM
        if verdict == "DROP":
            self.siem.forward({
                "type":  "drop",
                "src":   ip_src,
                "dport": dport,
                "proto": proto,
            })

        return verdict

    def _match_rules(self, ip_src, dport, proto) -> str:
        """First-match rule evaluation. Default verdict is ALLOW."""
        with self._lock:
            rules = list(self.rules)
        for rule in rules:
            if rule.get("ip")    and rule["ip"]    != ip_src : continue
            if rule.get("port")  and rule["port"]  != dport  : continue
            if rule.get("proto") and rule["proto"] != proto  : continue
            return rule["action"]
        return "ALLOW"

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
