"""Threat intel crawler: collect, process, and index public IOC/threat feeds."""

DOCUMENT_FIELDS = (
    "id",
    "actor",
    "category",
    "content",
    "platform",
    "publishDate",
    "website",
    "is_valid",
    "collectionDate",
    "linkToDataSource",
    "screenshots",
    "type",
)

__all__ = ["DOCUMENT_FIELDS"]
