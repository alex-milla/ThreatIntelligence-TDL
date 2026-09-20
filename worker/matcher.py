#!/usr/bin/env python3
"""Keyword matching engine.

Uses an Aho-Corasick automaton (pyahocorasick) when available: it finds every
keyword present in a domain in a single pass over the text, which is far faster
than looping over each keyword when many are defined. Falls back to simple
substring matching if the optional dependency is not installed.

Build a `Matcher` once and reuse it for many `match()` calls so the automaton
is only built a single time (important when matching in batches).
"""

from collections import defaultdict
from typing import Iterable

try:
    import ahocorasick
    _HAS_AHOCORASICK = True
except ImportError:  # optional accelerator
    _HAS_AHOCORASICK = False


def _split_domain(domain_lower: str) -> tuple[str, str]:
    """Return (name_part, tld), never matching against the TLD portion."""
    parts = domain_lower.rsplit(".", 1)
    if len(parts) > 1:
        return parts[0], parts[1]
    return domain_lower, ""


def _build_automaton(keyword_list: list[tuple[int, str]]):
    """Build an Aho-Corasick automaton that preserves duplicate keyword ids."""
    by_word: dict[str, list[int]] = defaultdict(list)
    for keyword_id, keyword_lower in keyword_list:
        by_word[keyword_lower].append(keyword_id)

    automaton = ahocorasick.Automaton()
    for word, ids in by_word.items():
        automaton.add_word(word, (ids, word))
    automaton.make_automaton()
    return automaton


class Matcher:
    """Pre-compiled keyword matcher (build once, reuse for many batches)."""

    def __init__(self, keywords: list[dict]):
        self.keyword_list = [(k["id"], k["keyword"].lower()) for k in keywords if k.get("keyword")]
        self._automaton = None
        if self.keyword_list and _HAS_AHOCORASICK:
            self._automaton = _build_automaton(self.keyword_list)

    def match(self, domains: Iterable[str]) -> list[dict]:
        """
        Compare each domain against keywords (substring, case-insensitive).

        Returns list of match dicts:
            [{'keyword_id': 1, 'domain': 'santander-bank.xyz', 'tld': 'xyz'}, ...]
        """
        matches: list[dict] = []
        if not self.keyword_list:
            return matches

        if self._automaton is not None:
            for domain in domains:
                name_part, tld = _split_domain(domain.lower())
                seen_ids: set[int] = set()
                for _, (ids, _word) in self._automaton.iter(name_part):
                    for keyword_id in ids:
                        # A keyword may occur several times in the same name;
                        # keep one match per (domain, keyword) as before.
                        if keyword_id in seen_ids:
                            continue
                        seen_ids.add(keyword_id)
                        matches.append({
                            "keyword_id": keyword_id,
                            "domain": domain,
                            "tld": tld,
                        })
            return matches

        for domain in domains:
            name_part, tld = _split_domain(domain.lower())
            for keyword_id, keyword_lower in self.keyword_list:
                # Match only in the name part, never in the TLD
                if keyword_lower in name_part:
                    matches.append({
                        "keyword_id": keyword_id,
                        "domain": domain,
                        "tld": tld,
                    })
        return matches


def match_domains(domains: Iterable[str], keywords: list[dict]) -> list[dict]:
    """Convenience wrapper that builds a Matcher for a single call."""
    return Matcher(keywords).match(domains)


def filter_keywords(keywords: list[dict], keyword_ids: Iterable[int] | None) -> list[dict]:
    """Return only the keywords whose id is in ``keyword_ids``.

    ``None`` or an empty collection means "all keywords" (no filter). Used by
    the recheck to scan the cached domains against a user-selected subset.
    """
    if not keyword_ids:
        return keywords
    wanted = set()
    for value in keyword_ids:
        try:
            wanted.add(int(value))
        except (TypeError, ValueError):
            continue
    if not wanted:
        return keywords
    return [k for k in keywords if _as_int(k.get("id")) in wanted]


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1

