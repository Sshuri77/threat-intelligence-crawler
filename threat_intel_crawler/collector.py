"""Fetch normalized documents from configured HTML pages (website_scraped source)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urljoin
from typing import Any

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, Error as PlaywrightError

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 60
USER_AGENT = "threat-intel-crawler/1.0 (python requests)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

ALTENENS_DEFAULT_URL = "https://altenens.is/"
SPEAR_DEFAULT_URL = "https://spear.cx/"

# Platforms that require Playwright to bypass Cloudflare protection
PLAYWRIGHT_PLATFORMS = {
    "spear_cx",
}

_CONTENT_MAX_LEN = 8000


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _collect_single_html_page(
    url: str,
    *,
    platform: str,
) -> list[dict[str, Any]]:
    """Fetch one HTML page and build a single normalized document."""
    url = (url or "").strip()
    if not url:
        return []
        
    if platform in PLAYWRIGHT_PLATFORMS:
        with sync_playwright() as p:
            # Launch with specific arguments to look less like a bot
            browser = p.chromium.launch(
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-setuid-sandbox"
                ]
            )
            # Create a context with a very common user agent
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                viewport={'width': 1920, 'height': 1080},
                device_scale_factor=1,
            )
            page = context.new_page()
            
            # Apply stealth
            try:
                from playwright_stealth import Stealth
                Stealth().apply_stealth_sync(page)
            except (ImportError, ModuleNotFoundError, AttributeError):
                # Silently skip if truly missing or if version mismatch
                pass

            # Navigate and wait for the initial load
            try:
                page.goto(url, wait_until="networkidle", timeout=REQUEST_TIMEOUT * 1000)
                
                # Cloudflare Check: If title still says "Just a moment", wait longer
                # We check for document.body to exist before accessing innerText
                page.wait_for_function(
                    '() => !document.title.includes("Just a moment") && (!document.body || !document.body.innerText.includes("Checking your browser"))',
                    timeout=30000
                )
                
                # Give it a few seconds to finish rendering after the challenge
                page.wait_for_timeout(5000)
                
            except PlaywrightError as e:
                # Log as info if it just timed out on the wait, as we might already have the content
                logger.info("Playwright wait completed or timed out: %s", e)
            
            screenshot_bytes = None
            try:
                # Capture a screenshot of the viewport
                screenshot_bytes = page.screenshot(full_page=False)
            except PlaywrightError as e:
                logger.warning("Failed to capture screenshot: %s", e)
                
            html = page.content()
            browser.close()
    else:
        r = SESSION.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        r.raise_for_status()
        html = r.text
        screenshot_bytes = None
    
    soup = BeautifulSoup(html, "html.parser")
    
    # Extract Title
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
        
    # Extract Description Meta Tag
    desc = ""
    for meta in soup.find_all("meta"):
        if meta.get("name", "").strip().lower() == "description":
            desc = meta.get("content", "").strip()
            break
            
    # Extract Date (Basic)
    # Search for <time> tags which are standard in XenForo and modern forums
    pub_date = ""
    time_tag = soup.find("time")
    if time_tag:
        # Try datetime or data-time attributes
        pub_date = time_tag.get("datetime") or time_tag.get("data-time") or time_tag.get_text().strip()
    
    if not pub_date:
        # Fallback: look for meta tags
        for meta in soup.find_all("meta"):
            m_prop = meta.get("property", "").lower()
            if "published_time" in m_prop or "updated_time" in m_prop:
                pub_date = meta.get("content", "")
                break

    # Extract Body Content (Targeted Extraction)
    # 1. Expand Noise Removal (decomposing non-essential elements)
    noise_selectors = [
        "script", "style", "nav", "footer", "header", "aside",
        "fieldset", ".p-nav", ".p-footer", ".p-sidebar", ".p-notices",
        ".stats", ".footer-links", ".p-breadcrumb", ".p-header"
    ]
    for selector in noise_selectors:
        for element in soup.select(selector) if selector.startswith(".") else soup.find_all(selector):
            element.decompose()

    target_keywords = ["latest posts", "databases", "leaks", "latest threads"]
    extracted_data = [] # List of dicts: [{"content": str, "actor": str}]

    # 2. Platform Specific Selection
    if platform == "spear_cx":
        # Sidebar blocks for "Latest Posts"
        for block in soup.select(".sidebar-block"):
            if any(k in block.get_text().lower() for k in target_keywords):
                username_el = block.select_one(".username, .author, [data-user-id]")
                actor = username_el.get_text(strip=True) if username_el else "unknown"
                extracted_data.append({
                    "content": block.get_text(separator=" ", strip=True),
                    "actor": actor
                })
        
        # Look for Forum Category rows/links
        for link in soup.find_all("a"):
            href = link.get("href", "").lower()
            if any(k in href for k in ["leaks", "databases"]):
                row = link.find_parent(["tr", "div", "li"])
                if row:
                    username_el = row.select_one(".username, .author, [data-user-id]")
                    actor = username_el.get_text(strip=True) if username_el else "unknown"
                    extracted_data.append({
                        "content": row.get_text(separator=" ", strip=True),
                        "actor": actor
                    })

    elif platform == "altenens_is": # (XenForo)
        # Latest Threads widget row
        for row in soup.select(".brmsRow"):
             username_el = row.select_one(".username, .author, [data-user-id]")
             actor = username_el.get_text(strip=True) if username_el else "unknown"
             extracted_data.append({
                 "content": row.get_text(separator=" ", strip=True),
                 "actor": actor
             })
        
        # Category Nodes (XF structure)
        for link in soup.find_all("a"):
            href = link.get("href", "").lower()
            if any(k in href for k in ["leaks", "database", "market"]):
                node = link.find_parent(["div", "li"], class_="node")
                if node:
                    username_el = node.select_one(".username, .author, [data-user-id]")
                    actor = username_el.get_text(strip=True) if username_el else "unknown"
                    extracted_data.append({
                        "content": node.get_text(separator=" ", strip=True),
                        "actor": actor
                    })

    # 3. Fallback: Search for keywords in general containers if nothing found yet
    if not extracted_data:
        for keyword in target_keywords:
            items = soup.find_all(string=lambda t: keyword in t.lower())
            for item in items:
                parent = item.find_parent(["div", "section", "article", "tr"])
                if parent:
                    username_el = parent.select_one(".username, .author, [data-user-id]")
                    actor = username_el.get_text(strip=True) if username_el else "unknown"
                    extracted_data.append({
                        "content": parent.get_text(separator=" ", strip=True),
                        "actor": actor
                    })

    # 4. Final Processing
    # Create the list of results
    results = []

    # A. Page Summary Document (type="page")
    all_text = " | ".join(d["content"] for d in extracted_data)
    summary_parts = [p for p in (title, desc, all_text) if p]
    summary_content = " | ".join(summary_parts) if summary_parts else url
    
    if len(summary_content) > _CONTENT_MAX_LEN:
        summary_content = summary_content[:_CONTENT_MAX_LEN]
        
    results.append({
        "id": "",
        "actor": "unknown", # For page summary, actor is generally unknown or site-wide
        "category": "unclassified",
        "content": summary_content,
        "platform": platform,
        "publishDate": pub_date,
        "website": url,
        "is_valid": True,
        "collectionDate": _now_iso(),
        "linkToDataSource": {
            "data_source": platform,
            "publishedOn": pub_date or None,
        },
        "screenshots": screenshot_bytes,
        "type": "page",
    })

    # B. Individual Thread Documents (type="thread")
    for item in extracted_data:
        # Avoid redundant summary duplicate if only one item found
        if item["content"].strip() == summary_content.strip():
            continue
            
        results.append({
            "id": "",
            "actor": item["actor"],
            "category": "unclassified",
            "content": item["content"],
            "platform": platform,
            "publishDate": pub_date,
            "website": url,
            "is_valid": True,
            "collectionDate": _now_iso(),
            "linkToDataSource": {
                "data_source": platform,
                "publishedOn": pub_date or None,
            },
            "screenshots": screenshot_bytes,
            "type": "thread",
        })

    return results


def _collect_altenens_source(*, altenens_url: str | None, **_: Any) -> list[dict[str, Any]]:
    url = (altenens_url or "").strip()
    if not url:
        logger.warning("No altenens_is URL configured; skipping source")
        return []
    chunk = _collect_single_html_page(url, platform="altenens_is")
    logger.info("altenens_is: %s documents", len(chunk))
    return chunk


def _collect_spear_source(*, spear_url: str | None, **_: Any) -> list[dict[str, Any]]:
    """Fetch threat intelligence content from spear.cx."""
    url = (spear_url or "").strip()
    if not url:
        logger.warning("No spear.cx URL configured; skipping source")
        return []
    chunk = _collect_single_html_page(url, platform="spear_cx")
    logger.info("spear_cx: %s documents", len(chunk))
    return chunk


SOURCE_RUNNERS = {
    "altenens_is": _collect_altenens_source,
    "spear_cx": _collect_spear_source,
}

DEFAULT_SOURCES = ["altenens_is", "spear_cx"]


def collect_all(
    *,
    altenens_url: str | None = ALTENENS_DEFAULT_URL,
    spear_url: str | None = SPEAR_DEFAULT_URL,
    enabled_sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run enabled collectors and return combined documents."""
    out: list[dict[str, Any]] = []
    selected = enabled_sources or DEFAULT_SOURCES
    for source_name in selected:
        runner = SOURCE_RUNNERS.get(source_name)
        if runner is None:
            logger.warning("Unknown source '%s'; skipping", source_name)
            continue
        try:
            out.extend(
                runner(
                    altenens_url=altenens_url,
                    spear_url=spear_url,
                )
            )
        except (requests.RequestException, PlaywrightError) as e:
            logger.error("%s collector failed: %s", source_name, e)
    return out
