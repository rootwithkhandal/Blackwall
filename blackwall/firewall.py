#!/usr/bin/env python3
"""
firewall.py — Core firewall engine.

Responsibilities:
  - Rule management (add / delete / persist)
  - Per-IP sliding-window rate limiting
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

# ── Paths ──────────────────────────────────────────────────────────────────────
_ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR  = os.path.join(_ROOT, "data")
RULES_FILE = os.path.join(_DATA_DIR, "rules.json")
BANS_FILE  = os.path.join(_DATA_DIR, "banned_ips.json")

# ── Rate-limit defaults ────────────────────────────────────────────────────────
RATE_LIMIT_THRESHOLD = 100   # packets per window before auto-ban
RATE_LIMIT_WINDOW    = 10    # seconds


class RateLimiter:
    """Sliding-window per-IP packet counter."""

    def __init__(
        self,
        threshold: int = RATE_LIMIT_THRESHOLD,
        window: int    = RATE_LIMIT_WINDOW,
    ):
        self.threshold = threshold
        self.window    = window
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record(self, ip: str) -> bool:
        """Record a packet hit. Returns True when the rate limit is exceeded."""
        now    = time.time()
        cutoff = now - self.window
        with self._lock:
            self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
            self._hits[ip].append(now)
            return len(self._hits[ip]) > self.threshold

    def reset(self, ip: str) -> None:
        with self._lock:
            self._hits.pop(ip, None)


class Firewall:
    def __init__(self, ledger: Blockchain):
        os.makedirs(_DATA_DIR, exist_ok=True)

        self.ledger       = ledger
        self.rules        : list[dict] = []
        self.banned_ips   : set[str]   = set()
        self.rate_limiter = RateLimiter()
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
        if not os.path.exists(RULES_FILE):
            return
        try:
            with open(RULES_FILE, "r") as f:
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
        tmp = RULES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.rules, f, indent=2)
        os.replace(tmp, RULES_FILE)

    # ------------------------------------------------------------------
    # Persistence — banned IPs
    # ------------------------------------------------------------------

    def _load_bans(self) -> None:
        """Restore banned IPs from disk so bans survive restarts."""
        if not os.path.exists(BANS_FILE):
            return
        try:
            with open(BANS_FILE, "r") as f:
                bans = json.load(f)
            self.banned_ips = set(bans)
            with self._lock:
                self._stats["banned"] = len(self.banned_ips)
        except (json.JSONDecodeError, TypeError):
            self.banned_ips = set()

    def _save_bans(self) -> None:
        tmp = BANS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(sorted(self.banned_ips), f, indent=2)
        os.replace(tmp, BANS_FILE)

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
            self._apply_iptables(rule, add=True)
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
            self._apply_iptables(removed_rule, add=False)   # remove from iptables
            self.ledger.add_block({"type": "rule_delete", "rule_id": rule_id})
            self.save_rules()
            return True
        return False

    def get_rules(self) -> list[dict]:
        with self._lock:
            return list(self.rules)

    # ------------------------------------------------------------------
    # iptables integration
    # ------------------------------------------------------------------

    def _apply_iptables(self, rule: dict, add: bool = True) -> None:
        """Add (-A) or delete (-D) a rule in the kernel iptables (Linux only)."""
        target = "DROP" if rule["action"] == "DROP" else "ACCEPT"
        flag   = "-A" if add else "-D"
        cmd    = ["sudo", "iptables", flag, "INPUT"]
        if rule.get("ip"):
            cmd += ["-s", rule["ip"]]
        if rule.get("port") and rule.get("proto"):
            cmd += ["-p", rule["proto"].lower(), "--dport", str(rule["port"])]
        cmd += ["-j", target]
        try:
            subprocess.run(cmd, check=False, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass   # iptables unavailable (Windows / rootless container)

    # ------------------------------------------------------------------
    # Auto-ban
    # ------------------------------------------------------------------

    def _ban_ip(self, ip: str) -> None:
        """Auto-ban an IP that exceeded the rate limit."""
        if ip in self.banned_ips:
            return
        self.banned_ips.add(ip)
        with self._lock:
            self._stats["banned"] += 1
        self._save_bans()
        self.add_rule(
            action  = "DROP",
            ip      = ip,
            comment = f"auto-ban: rate limit exceeded at {time.strftime('%H:%M:%S')}",
        )
        print(f"[fw] AUTO-BAN {ip}")

    def unban_ip(self, ip: str) -> bool:
        """
        Remove an IP from the ban list, reset its rate-limiter bucket,
        and delete the corresponding auto-ban DROP rule.
        Returns True if the IP was actually banned.
        """
        if ip not in self.banned_ips:
            return False

        self.banned_ips.discard(ip)
        self.rate_limiter.reset(ip)
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

        if IP in pkt:
            ip_src = pkt[IP].src
        if TCP in pkt:
            dport, proto = pkt[TCP].dport, "TCP"
        elif UDP in pkt:
            dport, proto = pkt[UDP].dport, "UDP"

        # Rate-limit check (only for known IPs)
        if ip_src and self.rate_limiter.record(ip_src):
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
