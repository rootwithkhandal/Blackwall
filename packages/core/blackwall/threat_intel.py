#!/usr/bin/env python3
import concurrent.futures
import ipaddress
import json
import os
import threading
import requests

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "").strip()
SHODAN_KEY    = os.environ.get("SHODAN_KEY", "").strip()

class ThreatIntel:
    def __init__(self, data_dir: str):
        self._cache_file = os.path.join(data_dir, "ip_intel.json")
        self._cache = {}
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self._cache_file):
            try:
                with open(self._cache_file, "r") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self):
        with self._lock:
            tmp = self._cache_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._cache, f, indent=2)
            os.replace(tmp, self._cache_file)

    def is_routable(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_global and not ip_obj.is_multicast
        except ValueError:
            return False

    def query_async(self, ip: str) -> None:
        # Ignore local/private IPs, unknowns, and already cached ones
        if not ip or ip == "unknown" or not self.is_routable(ip):
            return
            
        with self._lock:
            if ip in self._cache:
                return
            # Mark as pending to avoid duplicate parallel lookups
            self._cache[ip] = {"status": "pending"}

        self._executor.submit(self._fetch, ip)

    def _fetch(self, ip: str) -> None:
        result = {"abuse_score": None, "cves": [], "ports": []}
        
        if ABUSEIPDB_KEY:
            try:
                res = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 30},
                    timeout=5
                )
                if res.status_code == 200:
                    result["abuse_score"] = res.json().get("data", {}).get("abuseConfidenceScore", 0)
            except Exception:
                pass

        if SHODAN_KEY:
            try:
                res = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
                    timeout=5
                )
                if res.status_code == 200:
                    data = res.json()
                    result["cves"] = data.get("vulns", [])
                    result["ports"] = data.get("ports", [])
            except Exception:
                pass
                
        result["status"] = "complete"
                
        with self._lock:
            self._cache[ip] = result
        self._save_cache()

    def get(self, ip: str) -> dict | None:
        """Return the intel dict for an IP, or None if not queried or pending."""
        with self._lock:
            data = self._cache.get(ip)
        if data and data.get("status") == "complete":
            return data
        return None
