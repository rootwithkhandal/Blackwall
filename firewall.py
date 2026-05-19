#!/usr/bin/env python3
"""
firewall.py — Core firewall engine with rule management, rate limiting,
auto-ban, and iptables integration.
"""

import json
import os
import subprocess
import time
import threading
from collections import defaultdict
from scapy.all import IP, TCP, UDP
from blockchain import Blockchain

RULES_FILE = "rules.json"

# Rate-limit config: if a single IP sends more than RATE_LIMIT_THRESHOLD
# packets within RATE_LIMIT_WINDOW seconds it gets auto-banned.
RATE_LIMIT_THRESHOLD = 100   # packets
RATE_LIMIT_WINDOW    = 10    # seconds


class RateLimiter:
    """Sliding-window per-IP packet counter."""

    def __init__(self, threshold: int = RATE_LIMIT_THRESHOLD,
                 window: int = RATE_LIMIT_WINDOW):
        self.threshold = threshold
        self.window    = window
        # ip -> deque of timestamps
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record(self, ip: str) -> bool:
        """Record a hit for *ip*. Returns True if the rate limit is exceeded."""
        now = time.time()
        with self._lock:
            hits = self._hits[ip]
            # Prune old entries outside the window
            cutoff = now - self.window
            self._hits[ip] = [t for t in hits if t > cutoff]
            self._hits[ip].append(now)
            return len(self._hits[ip]) > self.threshold

    def reset(self, ip: str) -> None:
        with self._lock:
            self._hits.pop(ip, None)


class Firewall:
    def __init__(self, ledger: Blockchain):
        self.rules: list[dict] = []
        self.ledger = ledger
        self.banned_ips: set[str] = set()
        self.rate_limiter = RateLimiter()
        self._stats = {"total": 0, "allow": 0, "drop": 0, "banned": 0}
        self._lock = threading.Lock()
        self.load_rules()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load_rules(self) -> None:
        """Load rules from RULES_FILE without triggering iptables or ledger."""
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r") as f:
                    data = json.load(f)
                    for r in data:
                        self.add_rule(
                            action=r["action"],
                            ip=r.get("ip"),
                            port=r.get("port"),
                            proto=r.get("proto"),
                            comment=r.get("comment", ""),
                            log=False,
                            apply_iptables=False,
                        )
            except (json.JSONDecodeError, KeyError):
                print(f"[fw] {RULES_FILE} is empty or corrupted — starting fresh.")
                self.rules = []
        else:
            self.rules = []

    def save_rules(self) -> None:
        """Persist current rule list to RULES_FILE."""
        with open(RULES_FILE, "w") as f:
            json.dump(self.rules, f, indent=2)

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(
        self,
        action: str,
        ip: str | None = None,
        port: int | None = None,
        proto: str | None = None,
        comment: str = "",
        log: bool = True,
        apply_iptables: bool = True,
    ) -> dict:
        """Add a firewall rule and optionally push it to iptables."""
        rule = {
            "id":      len(self.rules),
            "action":  action.upper(),
            "ip":      ip,
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
            self._apply_iptables(rule)
        self.save_rules()
        return rule

    def delete_rule(self, rule_id: int) -> bool:
        """Remove a rule by its id field. Returns True on success."""
        with self._lock:
            original = len(self.rules)
            self.rules = [r for r in self.rules if r.get("id") != rule_id]
            removed = len(self.rules) < original
        if removed:
            self.ledger.add_block({"type": "rule_delete", "rule_id": rule_id})
            self.save_rules()
        return removed

    def get_rules(self) -> list[dict]:
        with self._lock:
            return list(self.rules)

    # ------------------------------------------------------------------
    # iptables integration
    # ------------------------------------------------------------------

    def _apply_iptables(self, rule: dict) -> None:
        """Push a single rule to the kernel via iptables (Linux only)."""
        target = "DROP" if rule["action"] == "DROP" else "ACCEPT"
        cmd = ["sudo", "iptables", "-A", "INPUT"]
        if rule.get("ip"):
            cmd += ["-s", rule["ip"]]
        if rule.get("port") and rule.get("proto"):
            cmd += ["-p", rule["proto"].lower(), "--dport", str(rule["port"])]
        cmd += ["-j", target]
        try:
            subprocess.run(cmd, check=False, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # iptables not available (Windows / container without it)
            pass

    def _ban_ip(self, ip: str) -> None:
        """Auto-ban an IP that exceeded the rate limit."""
        if ip in self.banned_ips:
            return
        self.banned_ips.add(ip)
        self._stats["banned"] += 1
        self.add_rule(
            action="DROP",
            ip=ip,
            comment=f"auto-ban: rate limit exceeded at {time.strftime('%H:%M:%S')}",
        )
        print(f"[fw] AUTO-BAN {ip}")

    # ------------------------------------------------------------------
    # Packet inspection
    # ------------------------------------------------------------------

    def check_packet(self, pkt) -> str:
        """Evaluate a Scapy packet against the rule list. Returns verdict string."""
        ip_src, dport, proto = None, None, None

        if IP in pkt:
            ip_src = pkt[IP].src
        if TCP in pkt:
            dport, proto = pkt[TCP].dport, "TCP"
        elif UDP in pkt:
            dport, proto = pkt[UDP].dport, "UDP"

        # Rate-limit check
        if ip_src and self.rate_limiter.record(ip_src):
            self._ban_ip(ip_src)

        # Already banned?
        if ip_src in self.banned_ips:
            verdict = "DROP"
        else:
            verdict = self._match_rules(ip_src, dport, proto)

        # Update stats
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
        print(f"[fw] {ip_src} -> port {dport}/{proto} verdict={verdict}")
        return verdict

    def _match_rules(self, ip_src, dport, proto) -> str:
        """Walk the rule list and return the first matching verdict."""
        with self._lock:
            rules = list(self.rules)
        for rule in rules:
            if rule.get("ip") and rule["ip"] != ip_src:
                continue
            if rule.get("port") and rule["port"] != dport:
                continue
            if rule.get("proto") and rule["proto"] != proto:
                continue
            return rule["action"]
        return "ALLOW"   # default-allow if no rule matches

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
