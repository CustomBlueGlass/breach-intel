"""
Generic JSON API collector base. Source-specific subclasses (see
collectors/sources/*.py) override `endpoint()`, `auth_headers()`, and
`map_item()` — everything else (pagination, fetching, fingerprinting via
the framework) is shared.
"""
from __future__ import annotations

import abc
from typing import Any

from app.collectors.base import BaseCollector, NormalizedRecord


class JSONAPICollector(BaseCollector):
    default_document_type = "advisory"

    @abc.abstractmethod
    def endpoint(self) -> str: ...

    def auth_headers(self) -> dict[str, str]:
        return {}

    def request_params(self) -> dict[str, Any]:
        return {}

    @abc.abstractmethod
    def map_item(self, item: dict) -> NormalizedRecord | None: ...

    def items_from_response(self, payload: Any) -> list[dict]:
        """Override if the source nests results, e.g. payload['data']['items']."""
        if isinstance(payload, list):
            return payload
        return payload.get("results") or payload.get("data") or payload.get("vulnerabilities") or []

    async def fetch_raw(self) -> Any:
        resp = await self.client.get(
            self.endpoint(), headers=self.auth_headers(), params=self.request_params()
        )
        resp.raise_for_status()
        return resp.json()

    async def parse(self, raw: Any) -> list[NormalizedRecord]:
        items = self.items_from_response(raw)
        out = []
        for item in items:
            rec = self.map_item(item)
            if rec:
                out.append(rec)
        return out
