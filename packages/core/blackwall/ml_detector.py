#!/usr/bin/env python3
"""
ml_detector.py — ML-based anomaly detection for Blackwall.

Replaces the pure rate-limit auto-ban with an IsolationForest model
trained on per-IP traffic features:
  - pkt_rate      : packets per second in the window
  - byte_rate     : bytes per second in the window
  - unique_ports  : number of distinct destination ports contacted
  - protocol_entropy : Shannon entropy over protocol distribution

Workflow:
  1. Collect traffic features for BASELINE_DURATION (default 5 min).
  2. Fit an IsolationForest on the baseline feature matrix.
  3. Score every subsequent window; flag IPs whose vector is an outlier.
"""

import math
import threading
import time
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

# ── Tunables ───────────────────────────────────────────────────────────────────
BASELINE_DURATION = 300       # seconds of traffic collection before first fit
WINDOW_SECONDS    = 10        # evaluation window length
CONTAMINATION     = 0.05      # expected fraction of anomalous windows
MIN_BASELINE_SAMPLES = 20    # minimum feature vectors before fitting


class _WindowBucket:
    """Accumulates raw packet stats for a single IP in one time window."""

    __slots__ = ("pkt_count", "byte_count", "ports", "proto_counts", "start")

    def __init__(self, start: float):
        self.pkt_count: int = 0
        self.byte_count: int = 0
        self.ports: set[int] = set()
        self.proto_counts: dict[str, int] = defaultdict(int)
        self.start: float = start


def _shannon_entropy(counts: dict[str, int]) -> float:
    """Compute Shannon entropy (bits) over a protocol frequency dict."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _bucket_to_features(bucket: _WindowBucket, elapsed: float) -> list[float]:
    """Convert a window bucket into the 4-element feature vector."""
    if elapsed <= 0:
        elapsed = 1e-6  # avoid division by zero
    pkt_rate       = bucket.pkt_count / elapsed
    byte_rate      = bucket.byte_count / elapsed
    unique_ports   = len(bucket.ports)
    proto_entropy  = _shannon_entropy(bucket.proto_counts)
    return [pkt_rate, byte_rate, unique_ports, proto_entropy]


class MLDetector:
    """
    IsolationForest-based per-IP anomaly detector.

    Thread-safe.  Call `record()` for every packet and `check_ip()` to
    see whether an IP's current window is anomalous.
    """

    def __init__(
        self,
        baseline_duration: int = BASELINE_DURATION,
        window_seconds: int    = WINDOW_SECONDS,
        contamination: float   = CONTAMINATION,
    ):
        self._baseline_duration = baseline_duration
        self._window            = window_seconds
        self._contamination     = contamination

        self._start_time = time.time()
        self._model: IsolationForest | None = None
        self._baseline_vectors: list[list[float]] = []
        self._fitted = False

        # Per-IP current window buckets
        self._buckets: dict[str, _WindowBucket] = defaultdict(
            lambda: _WindowBucket(time.time())
        )
        self._lock = threading.Lock()

    # ── Public API ─────────────────────────────────────────────────────

    @property
    def is_baseline_phase(self) -> bool:
        """True while still collecting the initial baseline."""
        return not self._fitted

    def record(self, ip: str, pkt_bytes: int, port: int | None, proto: str | None) -> None:
        """
        Record a single packet's metadata into the current window bucket
        for *ip*.  Called from Firewall.check_packet().
        """
        now = time.time()
        with self._lock:
            bucket = self._buckets[ip]

            # If the window has elapsed, finalise the old bucket first.
            elapsed = now - bucket.start
            if elapsed >= self._window:
                self._finalise_bucket(ip, bucket, elapsed)
                # Start a fresh bucket
                bucket = _WindowBucket(now)
                self._buckets[ip] = bucket

            bucket.pkt_count += 1
            bucket.byte_count += pkt_bytes
            if port is not None:
                bucket.ports.add(port)
            if proto:
                bucket.proto_counts[proto] += 1

    def check_ip(self, ip: str) -> bool:
        """
        Returns True if *ip*'s most-recent completed window was scored
        as anomalous by the IsolationForest.

        During the baseline phase this always returns False (no bans).
        """
        if not self._fitted:
            return False

        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                return False
            elapsed = time.time() - bucket.start
            if elapsed < self._window:
                # Window still open — score what we have so far.
                vec = _bucket_to_features(bucket, elapsed)
            else:
                vec = _bucket_to_features(bucket, elapsed)

        return self._score(vec)

    def reset(self, ip: str) -> None:
        """Remove all tracking state for *ip* (called on unban)."""
        with self._lock:
            self._buckets.pop(ip, None)

    # ── Internals ──────────────────────────────────────────────────────

    def _finalise_bucket(self, ip: str, bucket: _WindowBucket, elapsed: float) -> None:
        """
        Called (under lock) when a window expires.

        During baseline: stash the feature vector for training.
        After baseline:  (scoring happens in check_ip).
        """
        vec = _bucket_to_features(bucket, elapsed)

        if not self._fitted:
            self._baseline_vectors.append(vec)
            # Check if baseline period is over
            if (
                time.time() - self._start_time >= self._baseline_duration
                and len(self._baseline_vectors) >= MIN_BASELINE_SAMPLES
            ):
                self._fit_model()

    def _fit_model(self) -> None:
        """Train the IsolationForest on collected baseline vectors."""
        X = np.array(self._baseline_vectors)
        self._model = IsolationForest(
            contamination=self._contamination,
            n_estimators=100,
            random_state=42,
        )
        self._model.fit(X)
        self._fitted = True
        self._baseline_vectors = []  # free memory
        print(
            f"[ml] IsolationForest fitted on {len(X)} baseline samples "
            f"({self._baseline_duration}s collection period)."
        )

    def _score(self, vec: list[float]) -> bool:
        """Return True if *vec* is an outlier according to the fitted model."""
        if self._model is None:
            return False
        prediction = self._model.predict(np.array(vec).reshape(1, -1))
        # IsolationForest: -1 = outlier, 1 = inlier
        return prediction[0] == -1
