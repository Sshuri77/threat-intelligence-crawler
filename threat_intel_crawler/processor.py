"""Normalize, clean, and deduplicate threat intel documents."""

from __future__ import annotations

import hashlib
import base64
from datetime import datetime
from typing import Any

from threat_intel_crawler import DOCUMENT_FIELDS


def _clean_str(s: str | None) -> str:
    if s is None:
        return ""
    t = s.strip()
    t = " ".join(t.split())
    return t


def _normalize_publish_date(value: str) -> str:
    v = _clean_str(value)
    if not v:
        return ""
    candidate = v.replace("Z", "+00:00") if v.endswith("Z") else v
    try:
        dt = datetime.fromisoformat(candidate.replace(" ", "T", 1) if " " in candidate and "T" not in candidate else candidate)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return v


def _build_stable_id(doc: dict[str, Any]) -> str:
    raw = "|".join(
        (
            _clean_str(doc.get("platform")).lower(),
            _clean_str(doc.get("website")).lower(),
            _clean_str(doc.get("category")).lower(),
            _clean_str(doc.get("content")).lower(),
        )
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _doc_key(doc: dict[str, Any]) -> tuple[str, str, str]:
    # Deduplicate by: stable hash id + platform + website URL
    # This prevents the same article from being indexed twice in one run
    return (
        _clean_str(doc.get("id")),
        _clean_str(doc.get("platform")).lower(),
        _clean_str(doc.get("website")).lower(),
    )


def ensure_schema(doc: dict[str, Any]) -> dict[str, Any]:
    """Return a document with exactly DOCUMENT_FIELDS; missing values filled."""
    out: dict[str, Any] = {}
    for k in DOCUMENT_FIELDS:
        if k == "is_valid":
            v = doc.get(k, True)
            out[k] = bool(v) if not isinstance(v, str) else v.lower() in ("1", "true", "yes")
        elif k == "publishDate" or k == "collectionDate":
            p = doc.get(k, "")
            out[k] = _normalize_publish_date(p) if isinstance(p, str) else ""
        elif k == "id":
            raw_id = doc.get(k, "")
            out[k] = _clean_str(raw_id) if isinstance(raw_id, str) else ""
        elif k == "linkToDataSource":
            raw_link = doc.get(k) or {}
            out[k] = {
                "data_source": _clean_str(raw_link.get("data_source")) if isinstance(raw_link, dict) else "",
                "publishedOn": _normalize_publish_date(raw_link.get("publishedOn") or "") if isinstance(raw_link, dict) else None,
            }
        elif k == "screenshots":
            raw_s = doc.get(k)
            if isinstance(raw_s, bytes):
                out[k] = base64.b64encode(raw_s).decode("utf-8")
            else:
                out[k] = None
        elif k == "type":
            out[k] = _clean_str(doc.get(k, ""))
        else:
            raw = doc.get(k, "")
            out[k] = _clean_str(raw) if isinstance(raw, str) else str(raw or "")
    if not out.get("id"):
        out["id"] = _build_stable_id(out)
    return out


def process(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Clean, normalize, deduplicate (keep first occurrence per key)."""
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for raw in documents:
        doc = ensure_schema(raw)
        key = _doc_key(doc)
        if not (doc.get("content") or doc.get("website")):
            continue
        if key in seen:
            continue
        seen.add(key)
        result.append(doc)
    return result
