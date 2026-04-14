"""Index and search threat intel documents in Elasticsearch."""

from __future__ import annotations

import logging
import os
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logger = logging.getLogger(__name__)

DEFAULT_INDEX = "threat_intel"
DEFAULT_HOST = os.environ.get("ELASTICSEARCH_URL", "https://X.X.X.X")
def _auth_tuple(
    username: str | None,
    password: str | None,
) -> tuple[str, str] | None:
    user = (username or "").strip() or os.environ.get("ELASTICSEARCH_USERNAME")
    pw = (password or "").strip() or os.environ.get("ELASTICSEARCH_PASSWORD")
    if user and pw:
        return (user, pw)
    return None

MAPPING_PROPERTIES: dict[str, Any] = {
    "actor": {"type": "keyword", "ignore_above": 256},
    "category": {"type": "keyword", "ignore_above": 256},
    "collectionDate": {"type": "date"},
    "content": {"type": "text"},
    "id": {"type": "keyword", "ignore_above": 256},
    "is_valid": {"type": "boolean"},
    "linkToDataSource": {
        "properties": {
            "data_source": {"type": "keyword"},
            "publishedOn": {"type": "date", "format": "yyyy-MM-dd||strict_date_optional_time"}
        }
    },
    "platform": {"type": "keyword", "ignore_above": 256},
    "publishDate": {"type": "date"},
    "screenshots": {"type": "binary"},
    "type": {"type": "keyword"},
    "website": {"type": "keyword", "ignore_above": 256},
}


def get_client(
    hosts: str | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
    **kwargs: Any,
) -> Elasticsearch:
    url = (hosts or DEFAULT_HOST).rstrip("/")
    opts: dict[str, Any] = {
        "max_retries": 0,
        "retry_on_timeout": False,
        "request_timeout": 8,
    }
    if url.lower().startswith("https://"):
        opts["verify_certs"] = False
        opts["ssl_show_warn"] = False
    opts.update(kwargs)
    auth = _auth_tuple(username, password)
    if auth:
        opts["basic_auth"] = auth
    return Elasticsearch(url, **opts)


def ensure_index(es: Elasticsearch, index: str = DEFAULT_INDEX) -> None:
    if es.indices.exists(index=index):
        return
    es.indices.create(
        index=index,
        mappings={"properties": MAPPING_PROPERTIES},
    )
    logger.info("Created index %s", index)


def _sanitize_doc(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    for key in ("publishDate", "collectionDate"):
        if out.get(key) == "":
            out[key] = None
            
    link = out.get("linkToDataSource")
    if isinstance(link, dict):
        new_link = dict(link)
        if new_link.get("publishedOn") == "":
            new_link["publishedOn"] = None
        out["linkToDataSource"] = new_link
        
    return out


def index_documents(
    es: Elasticsearch,
    documents: list[dict[str, Any]],
    index: str = DEFAULT_INDEX,
) -> int:
    actions = [
        {
            "_index": index,
            "_id": doc.get("id"),
            "_source": _sanitize_doc(doc),
        }
        for doc in documents
    ]
    ok, errors = bulk(es, actions, raise_on_error=False)
    if errors:
        logger.warning("Bulk had errors: %s", errors[:3])
    es.indices.refresh(index=index)
    return ok


def filter_new_documents(
    es: Elasticsearch,
    documents: list[dict[str, Any]],
    index: str = DEFAULT_INDEX,
) -> list[dict[str, Any]]:
    """Return only documents whose id is not yet indexed."""
    ids = [str(doc.get("id", "")).strip() for doc in documents if str(doc.get("id", "")).strip()]
    if not ids:
        return documents
    resp = es.mget(index=index, ids=ids)
    existing = {hit.get("_id") for hit in resp.get("docs", []) if hit.get("found")}
    return [doc for doc in documents if str(doc.get("id", "")).strip() not in existing]


def search_keyword(
    es: Elasticsearch,
    keyword: str,
    index: str = DEFAULT_INDEX,
    size: int = 50,
) -> list[dict[str, Any]]:
    resp = es.search(
        index=index,
        query={
            "multi_match": {
                "query": keyword,
                "fields": ["content^2", "actor", "category", "platform", "website"],
                "type": "best_fields",
            }
        },
        size=size,
    )
    hits = resp.get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]
