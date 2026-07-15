"""
Generic tabular (CSV/XLSX) collector. Used for sources that publish their
breach list as a downloadable dataset (HHS OCR portal export, Mass.gov
annual reports, Washington AG dataset, Privacy Rights Clearinghouse
chronology). XLSX support is included since several state AG offices
prefer Excel exports over CSV.
"""
from __future__ import annotations

import abc
import csv
import io

import openpyxl

from app.collectors.base import BaseCollector, NormalizedRecord


class TabularCollector(BaseCollector):
    default_document_type = "ag_notification_letter"
    file_kind: str = "csv"  # or "xlsx"

    async def fetch_raw(self) -> bytes:
        resp = await self.client.get(self.source_row.feed_url)
        resp.raise_for_status()
        return resp.content

    def rows(self, raw: bytes) -> list[dict]:
        if self.file_kind == "xlsx":
            wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
            ws = wb.active
            header = [str(c.value).strip() if c.value else "" for c in next(ws.iter_rows(max_row=1))]
            out = []
            for row in ws.iter_rows(min_row=2, values_only=True):
                out.append(dict(zip(header, row)))
            return out
        text = raw.decode("utf-8", errors="ignore")
        return list(csv.DictReader(io.StringIO(text)))

    @abc.abstractmethod
    def map_row(self, row: dict) -> NormalizedRecord | None: ...

    async def parse(self, raw: bytes) -> list[NormalizedRecord]:
        out = []
        for row in self.rows(raw):
            rec = self.map_row(row)
            if rec:
                out.append(rec)
        return out
