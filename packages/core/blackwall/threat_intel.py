#!/usr/bin/env python3
"""
threat_intel.py — Minimal threat intel lookup.
"""
import requests

def get_threat_intel(ip: str) -> dict:
    """Minimal lookup for a given IP."""
    # In a real scenario, this would query Shodan/VT.
    # For now, it returns a static dictionary.
    return {
        "ip": ip,
        "malicious": False,
        "score": 0,
        "tags": []
    }
