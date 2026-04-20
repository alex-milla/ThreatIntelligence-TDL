#!/usr/bin/env python3
"""Keyword matching engine."""

from typing import Iterable


def match_domains(domains: Iterable[str], keywords: list[dict]) -> list[dict]:
    """
    Compare each domain against keywords (substring, case-insensitive).
    
    domains: iterable of domain strings, e.g., 'santander-bank.xyz'
    keywords: list of dicts with keys 'id', 'keyword', e.g.,
              [{'id': 1, 'keyword': 'santander'}, ...]
    
    Returns list of match dicts:
        [{'keyword_id': 1, 'domain': 'santander-bank.xyz', 'tld': 'xyz'}, ...]
    """
    matches = []
    keyword_list = [(k["id"], k["keyword"].lower()) for k in keywords if k.get("keyword")]

    for domain in domains:
        domain_lower = domain.lower()
        # Extract TLD from domain (last dot-separated part)
        parts = domain_lower.rsplit(".", 1)
        tld = parts[1] if len(parts) > 1 else ""

        for keyword_id, keyword_lower in keyword_list:
            if keyword_lower in domain_lower:
                matches.append({
                    "keyword_id": keyword_id,
                    "domain": domain,
                    "tld": tld,
                })
                # One domain can match multiple keywords, but we don't break here
                # because we want all keyword matches.
    return matches
