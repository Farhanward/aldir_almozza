"""Aldir Almozza signal aggregation as a local HTTP service.

``POST /api/aggregate`` accepts ``{"signals": [...]}`` and returns the
consensus blocklist with fingerprints and severity counts — nodes can push
their local detections and pull a shared defense list.
"""

from __future__ import annotations

from http.server import ThreadingHTTPServer
from typing import Any

from .http_base import BaseServiceHandler, build_server
from .signals import aggregate


def _aggregate_route(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    signals = data.get("signals")
    if not isinstance(signals, list) or not signals:
        return 400, {"ok": False, "error": "missing non-empty 'signals' list"}
    if len(signals) > 50_000:
        return 400, {"ok": False, "error": "too many signals in one request (max 50000)"}
    threshold = data.get("block_threshold") or 70
    try:
        threshold = max(1, min(200, int(threshold)))
    except (TypeError, ValueError):
        threshold = 70
    return 200, {"ok": True, **aggregate(signals, block_threshold=threshold)}


class Handler(BaseServiceHandler):
    post_routes = {"/api/aggregate": staticmethod(_aggregate_route)}


def create_server(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    return build_server(Handler, host=host, port=port)


def run_server(host: str | None = None, port: int | None = None) -> None:
    from .version import __version__

    server = create_server(host=host, port=port)
    print(f"aldir service v{__version__}: http://{server.server_address[0]}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
