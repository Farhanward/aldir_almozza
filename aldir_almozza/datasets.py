from __future__ import annotations

import json
from pathlib import Path


def convert_nvd(input_path: str | Path, out_path: str | Path, *, limit: int = 0) -> dict:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = high = 0
    with Path(input_path).open("r", encoding="utf-8") as handle, out.open("w", encoding="utf-8") as output:
        for line in handle:
            if limit and rows >= limit:
                break
            if not line.strip():
                continue
            rec = json.loads(line)
            sev = str(rec.get("severity") or rec.get("baseSeverity") or "LOW").upper()
            cve = str(rec.get("id") or f"CVE-SIGNAL-{rows}")
            output.write(json.dumps({"kind": "cve", "value": cve, "severity": sev, "source": f"node-{rows % 9}"}, ensure_ascii=False) + "\n")
            rows += 1
            high += 1 if sev in {"CRITICAL", "HIGH"} else 0
    return {"out": str(out.resolve()), "rows": rows, "high": high}

