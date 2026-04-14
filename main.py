#!/usr/bin/env python3
"""CLI: full scrape pipeline or keyword search against Elasticsearch."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Allow running as `python main.py` from project root without install
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from elastic_transport import ConnectionError as ESConnectionError
from elasticsearch import ApiError

from threat_intel_crawler.collector import collect_all
from threat_intel_crawler.elasticsearch_index import (
    DEFAULT_HOST,
    DEFAULT_INDEX,
    ensure_index,
    filter_new_documents,
    get_client,
    index_documents,
    search_keyword,
)
from threat_intel_crawler.processor import process

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s %(message)s",
)
logging.getLogger("elastic_transport").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def cmd_scrape(args: argparse.Namespace) -> int:
    enabled_sources: list[str] = []
    if not args.no_altenens and args.altenens_url:
        enabled_sources.append("altenens_is")
    if not args.no_spear and args.spear_url:
        enabled_sources.append("spear_cx")
    raw = collect_all(
        altenens_url=args.altenens_url,
        spear_url=args.spear_url,
        enabled_sources=enabled_sources,
    )
    docs = process(raw)
    if getattr(args, "keyword_filter", None):
        kw = args.keyword_filter.lower()
        docs = [d for d in docs if kw in str(d.get("content") or "").lower()]
        logger.info("Filtered by keyword '%s'. Matches remaining: %s", args.keyword_filter, len(docs))
    logger.info("After processing: %s documents", len(docs))
    try:
        es = get_client(
            hosts=args.es_url,
            username=args.es_user,
            password=args.es_password,
        )
        ensure_index(es, index=args.index)  # mapping created only once per run
        new_docs = filter_new_documents(es, docs, index=args.index)
        logger.info("New documents to index: %s/%s", len(new_docs), len(docs))
        if new_docs:
            sample = new_docs[:5]
            for i, d in enumerate(sample, 1):
                title_like = (d.get("content") or "")[:120]
                logger.info("NEW %s: %s (%s)", i, title_like, d.get("website"))
        n = index_documents(es, new_docs, index=args.index)
    except ESConnectionError as e:
        logger.error("Cannot reach Elasticsearch at %s: %s", args.es_url, e)
        return 1
    except ApiError as e:
        logger.error("Elasticsearch error: %s", e)
        return 1
    logger.info("Indexed %s documents into %s", n, args.index)
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    try:
        es = get_client(
            hosts=args.es_url,
            username=args.es_user,
            password=args.es_password,
        )
        results = search_keyword(es, args.keyword, index=args.index, size=args.limit)
    except ESConnectionError as e:
        logger.error("Cannot reach Elasticsearch at %s: %s", args.es_url, e)
        return 1
    except ApiError as e:
        logger.error("Elasticsearch error: %s", e)
        return 1
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for i, doc in enumerate(results, 1):
            print(f"--- {i} ---")
            for k in sorted(doc.keys()):
                print(f"  {k}: {doc[k]}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Threat intel crawler")
    p.add_argument(
        "--es-url",
        default=DEFAULT_HOST,
        help=f"Elasticsearch URL (default: {DEFAULT_HOST} or ELASTICSEARCH_URL)",
    )
    p.add_argument(
        "--es-user",
        default=os.environ.get("ELASTICSEARCH_USERNAME"),
        help="Elasticsearch username (env: ELASTICSEARCH_USERNAME)",
    )
    p.add_argument(
        "--es-password",
        default=os.environ.get("ELASTICSEARCH_PASSWORD"),
        help="Elasticsearch password (env: ELASTICSEARCH_PASSWORD)",
    )
    p.add_argument("--index", default=DEFAULT_INDEX, help="Index name")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scrape", help="Collect, process, and index configured sources")
    s.add_argument(
        "--altenens-url",
        default="https://altenens.is/",
        help="URL for altenens_is source; use empty string to skip",
    )
    s.add_argument(
        "--no-altenens",
        action="store_true",
        help="Disable the altenens_is collector",
    )
    s.add_argument(
        "--spear-url",
        default="https://spear.cx/",
        help="URL for spear.cx source; use empty string to skip",
    )
    s.add_argument(
        "--no-spear",
        action="store_true",
        help="Disable the spear.cx collector",
    )
    s.add_argument(
        "--keyword-filter",
        default=None,
        help="Only index scraped documents containing this keyword in their content",
    )
    s.set_defaults(func=cmd_scrape)

    q = sub.add_parser("search", help="Keyword search in Elasticsearch")
    q.add_argument("keyword", help="Search string")
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--json", action="store_true", help="Print JSON array")
    q.set_defaults(func=cmd_search)

    args = p.parse_args()
    if getattr(args, "no_altenens", False):
        args.altenens_url = None
    elif getattr(args, "altenens_url", None) == "":
        args.altenens_url = None
    if getattr(args, "no_spear", False):
        args.spear_url = None
    elif getattr(args, "spear_url", None) == "":
        args.spear_url = None
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
