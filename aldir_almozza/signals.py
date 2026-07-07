from __future__ import annotations

import hashlib
from collections import Counter


def normalize_signal(signal: dict) -> dict:
    kind = str(signal.get("kind") or "cve").lower()
    value = str(signal.get("value") or signal.get("id") or "").strip().lower()
    severity = str(signal.get("severity") or "low").upper()
    source = str(signal.get("source") or "local")
    fingerprint = hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:24]
    score = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 45, "LOW": 20}.get(severity, 10)
    return {"kind": kind, "value": value, "severity": severity, "source": source, "fingerprint": fingerprint, "score": score}


def aggregate(signals: list[dict], *, block_threshold: int = 70) -> dict:
    normalized = [normalize_signal(item) for item in signals]
    grouped: dict[str, list[dict]] = {}
    for item in normalized:
        grouped.setdefault(item["fingerprint"], []).append(item)
    blocklist = []
    for fp, items in grouped.items():
        score = max(item["score"] for item in items) + 5 * (len({item["source"] for item in items}) - 1)
        if score >= block_threshold:
            blocklist.append({"fingerprint": fp, "kind": items[0]["kind"], "value": items[0]["value"], "score": score, "reports": len(items)})
    counts = Counter(item["severity"] for item in normalized)
    return {"signals": len(normalized), "unique": len(grouped), "blocklist": blocklist, "severity_counts": dict(counts)}

