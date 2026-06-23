#!/usr/bin/env python3
"""
siem_forwarder.py — Fire-and-forget alert forwarder to Splunk HEC and Wazuh.

Reads configuration from environment variables:
  - SPLUNK_HEC_URL   : Splunk HTTP Event Collector endpoint
  - SPLUNK_HEC_TOKEN : Splunk HEC authentication token
  - WAZUH_SOCKET_PATH: Path to the Wazuh agent Unix domain socket

If neither is configured, the forwarder becomes a zero-overhead no-op.
Events are enqueued and dispatched by a single daemon worker thread so
the packet-processing path is never blocked by network I/O.
"""

import json
import os
import queue
import socket
import sys
import threading
import time

import requests

# ── Configuration from environment ─────────────────────────────────────────────
SPLUNK_HEC_URL   = os.environ.get("SPLUNK_HEC_URL", "").strip()
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
WAZUH_SOCKET_PATH = os.environ.get("WAZUH_SOCKET_PATH", "").strip()
WEBHOOK_URL       = os.environ.get("WEBHOOK_URL", "").strip()

# Retry / backoff
_MAX_RETRIES  = 3
_RETRY_DELAY  = 2        # seconds between retries
_HTTP_TIMEOUT = 5         # seconds


class SIEMForwarder:
    """
    Non-blocking SIEM alert forwarder.

    Usage::

        fwd = SIEMForwarder()
        fwd.forward({"type": "auto_ban", "ip": "10.0.0.5", ...})

    If no SIEM endpoints are configured via env vars, ``forward()`` is a
    no-op and no background thread is started.
    """

    def __init__(
        self,
        splunk_url: str | None = None,
        splunk_token: str | None = None,
        wazuh_socket: str | None = None,
    ):
        self._splunk_url   = splunk_url or SPLUNK_HEC_URL
        self._splunk_token = splunk_token or SPLUNK_HEC_TOKEN
        self._wazuh_socket = wazuh_socket or WAZUH_SOCKET_PATH
        self._webhook_url  = WEBHOOK_URL

        self._has_splunk = bool(self._splunk_url and self._splunk_token)
        self._has_wazuh  = bool(self._wazuh_socket)
        self._enabled    = self._has_splunk or self._has_wazuh or bool(self._webhook_url)

        self._queue: queue.Queue[dict] = queue.Queue(maxsize=2048)

        if self._enabled:
            self._worker = threading.Thread(target=self._run, daemon=True)
            self._worker.start()
            targets = []
            if self._has_splunk:
                targets.append("Splunk HEC")
            if self._has_wazuh:
                targets.append(f"Wazuh ({self._wazuh_socket})")
            if self._webhook_url:
                targets.append("Webhook (Discord/Slack)")
            print(f"[siem] Forwarder active → {', '.join(targets)}")
        else:
            self._worker = None

    # ── Public API ─────────────────────────────────────────────────────

    def forward(self, event: dict) -> None:
        """
        Enqueue an event for forwarding.  Non-blocking.
        Silently drops if the queue is full (back-pressure safety valve).
        """
        if not self._enabled:
            return
        # Stamp the event
        event.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        event.setdefault("source", "blackwall")
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            print("[siem] Queue full — dropping event", file=sys.stderr)

    def forward_webhook(self, message: str) -> None:
        """
        Immediately enqueue a generic alert string to be sent to the configured Webhook URL.
        """
        if not self._webhook_url:
            return
        
        # If it's a discord URL without /slack, we should use 'content', otherwise 'text'
        if "discord.com" in self._webhook_url and not self._webhook_url.endswith("/slack"):
            payload = {"content": message}
        else:
            payload = {"text": message}
            
        try:
            self._queue.put_nowait({"_webhook_payload": payload})
        except queue.Full:
            pass

    # ── Worker loop ────────────────────────────────────────────────────

    def _run(self) -> None:
        """Daemon worker: drain queue → send to configured SIEM targets."""
        while True:
            try:
                event = self._queue.get()
            except Exception:
                continue

            if "_webhook_payload" in event:
                self._send_webhook(event["_webhook_payload"])
                continue

            if self._has_splunk:
                self._send_splunk(event)
            if self._has_wazuh:
                self._send_wazuh(event)

    # ── Splunk HEC ─────────────────────────────────────────────────────

    def _send_splunk(self, event: dict) -> None:
        """POST event to Splunk HEC with retries."""
        headers = {"Authorization": f"Splunk {self._splunk_token}"}
        payload = {"event": event}

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = requests.post(
                    self._splunk_url,
                    headers=headers,
                    json=payload,
                    timeout=_HTTP_TIMEOUT,
                    verify=True,
                )
                if resp.status_code < 300:
                    return
                print(
                    f"[siem] Splunk HEC {resp.status_code} (attempt {attempt}/{_MAX_RETRIES})",
                    file=sys.stderr,
                )
            except requests.RequestException as exc:
                print(
                    f"[siem] Splunk HEC error: {exc} (attempt {attempt}/{_MAX_RETRIES})",
                    file=sys.stderr,
                )
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)

    # ── Wazuh agent socket ─────────────────────────────────────────────

    def _send_wazuh(self, event: dict) -> None:
        """Write a JSON line to the Wazuh agent Unix domain socket."""
        msg = f"1:blackwall:{json.dumps(event)}"
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                sock.sendto(msg.encode(), self._wazuh_socket)
                sock.close()
                return
            except (OSError, socket.error) as exc:
                print(
                    f"[siem] Wazuh socket error: {exc} (attempt {attempt}/{_MAX_RETRIES})",
                    file=sys.stderr,
                )
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)

    # ── Discord/Slack Webhook ──────────────────────────────────────────

    def _send_webhook(self, payload: dict) -> None:
        """POST generic message to Discord or Slack."""
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = requests.post(
                    self._webhook_url,
                    json=payload,
                    timeout=_HTTP_TIMEOUT,
                )
                if resp.status_code < 300:
                    return
                print(
                    f"[siem] Webhook {resp.status_code} (attempt {attempt}/{_MAX_RETRIES})",
                    file=sys.stderr,
                )
            except requests.RequestException as exc:
                print(
                    f"[siem] Webhook error: {exc} (attempt {attempt}/{_MAX_RETRIES})",
                    file=sys.stderr,
                )
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
