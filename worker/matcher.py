#!/usr/bin/env python3
"""Keyword matching engine.

Two kinds of keyword match are applied together, so a keyword covers both:

  * ``literal``: case-insensitive substring, the long-standing behaviour.
    Accelerated with an Aho-Corasick automaton (pyahocorasick) when available;
    otherwise a simple substring loop.
  * ``glob``: a safe pattern subset — ``*`` (any sequence), ``?`` (one char),
    ``[abc]`` / ``[0-9]`` character classes (``[!...]`` negation) and ``{n,m}``
    repetition. It matches anywhere in the domain name part (no TLD).

Every keyword is matched literally, and additionally as a glob when it contains
a glob metacharacter (``* ? [ ] { }``); a match on either form counts. No type
has to be chosen.

Glob patterns are compiled to a regex once. To keep the full-cache recheck fast,
each glob also yields its longest mandatory literal ("anchor"); the regex is only
run on domains that contain the anchor (found with a second Aho-Corasick
automaton). Patterns without a usable anchor (< 3 literal chars) are skipped by
the recheck (``for_recheck=True``) but are still applied to the few new domains
of a daily scan.

Build a ``Matcher`` once and reuse it for many ``match()`` calls.
"""

import re
from collections import defaultdict
from typing import Iterable

try:
    import ahocorasick
    _HAS_AHOCORASICK = True
except ImportError:  # optional accelerator
    _HAS_AHOCORASICK = False

_ANCHOR_MIN = 3
_QUANT_MAX = 100


def is_glob(match_type, keyword: str) -> bool:
    """Deprecated: glob-ness is now detected from the keyword syntax."""
    return has_glob_chars(keyword)


def has_glob_chars(keyword: str) -> bool:
    """Whether a keyword contains a glob metacharacter (``* ? [ ] { }``)."""
    return any(ch in str(keyword or "") for ch in "*?[]{}")


def glob_to_regex(pattern: str) -> tuple[re.Pattern, str]:
    """Compile a glob to a case-insensitive regex and return (regex, anchor).

    The anchor is the longest run of mandatory literal characters, used to
    pre-filter candidates before running the regex.
    """
    out: list[str] = []
    best_anchor = ""
    cur: list[str] = []

    def flush_run(extra: str = "") -> None:
        nonlocal best_anchor
        run = "".join(cur)
        if extra:
            run += extra
        if len(run) > len(best_anchor):
            best_anchor = run

    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            flush_run()
            out.append(re.escape("".join(cur)))
            cur = []
            out.append(".*")
            i += 1
        elif c == "?":
            flush_run()
            out.append(re.escape("".join(cur)))
            cur = []
            out.append(".")
            i += 1
        elif c == "[":
            flush_run()
            out.append(re.escape("".join(cur)))
            cur = []
            j = i + 1
            negate = False
            if j < n and pattern[j] in ("!", "^"):
                negate = True
                j += 1
            start = j
            if j < n and pattern[j] == "]":  # leading ] is literal
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:  # unterminated class -> literal '['
                out.append(re.escape("["))
                i += 1
                continue
            content = pattern[start:j].replace("\\", "\\\\")
            out.append("[" + ("^" if negate else "") + content + "]")
            i = j + 1
        elif c == "{":
            m = re.match(r"\{(\d+)(,(\d*))?\}", pattern[i:])
            if not m:
                cur.append(c)
                i += 1
                continue
            inner = m.group(0)[1:-1].split(",")

            def _cap(x: str) -> str:
                return str(min(int(x), _QUANT_MAX)) if x.strip().isdigit() else ""

            if len(inner) == 1:
                quant = "{" + _cap(inner[0]) + "}"
                min_n = int(inner[0]) if inner[0].strip().isdigit() else 1
            else:
                lo = _cap(inner[0]) if inner[0].strip() else "0"
                hi = _cap(inner[1]) if inner[1].strip() else ""
                quant = "{" + lo + "," + hi + "}"
                min_n = int(lo) if lo else 0
            if cur:
                atom = cur[-1]
                run = "".join(cur[:-1])
                flush_run(atom if min_n >= 1 else "")
                out.append(re.escape(run))
                out.append(re.escape(atom))
            out.append(quant)
            cur = []
            i += m.end()
        else:
            cur.append(c)
            i += 1

    flush_run()
    out.append(re.escape("".join(cur)))
    regex = "".join(out)
    try:
        compiled = re.compile(regex, re.IGNORECASE)
    except re.error:
        compiled = re.compile(re.escape(pattern), re.IGNORECASE)
        best_anchor = pattern
    return compiled, best_anchor


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

    def __init__(self, keywords: list[dict], for_recheck: bool = False):
        self.for_recheck = for_recheck
        self.keyword_list: list[tuple[int, str]] = []
        self._anchor_map: dict[str, list[tuple[int, re.Pattern]]] = {}
        self._anchorless: list[tuple[int, re.Pattern]] = []

        anchors: dict[str, list[tuple[int, re.Pattern]]] = defaultdict(list)
        for k in keywords:
            kw = k.get("keyword")
            if not kw:
                continue
            kid = k.get("id")
            text = str(kw).lower()
            # Every keyword is matched literally; patterns additionally as a glob.
            self.keyword_list.append((kid, text))
            if has_glob_chars(text):
                compiled, anchor = glob_to_regex(text)
                if len(anchor) >= _ANCHOR_MIN:
                    anchors[anchor].append((kid, compiled))
                else:
                    self._anchorless.append((kid, compiled))

        self._anchor_map = dict(anchors)
        self._automaton = None
        if self.keyword_list and _HAS_AHOCORASICK:
            self._automaton = _build_automaton(self.keyword_list)

        self._anchor_automaton = None
        if anchors and _HAS_AHOCORASICK:
            automaton = ahocorasick.Automaton()
            for anchor, pats in anchors.items():
                automaton.add_word(anchor, (anchor, pats))
            automaton.make_automaton()
            self._anchor_automaton = automaton

    def has_keywords(self) -> bool:
        return bool(self.keyword_list or self._anchor_map or self._anchorless)

    def _emit(self, matches, seen, kid, domain, tld) -> None:
        if kid in seen:
            return
        seen.add(kid)
        matches.append({"keyword_id": kid, "domain": domain, "tld": tld})

    def match(self, domains: Iterable[str]) -> list[dict]:
        """Return matches: [{'keyword_id', 'domain', 'tld'}, ...]."""
        matches: list[dict] = []
        if not self.has_keywords():
            return matches
        include_anchorless = not self.for_recheck

        for domain in domains:
            name_part, tld = _split_domain(domain.lower())
            seen: set = set()

            if self._automaton is not None:
                for _, (ids, _word) in self._automaton.iter(name_part):
                    for kid in ids:
                        self._emit(matches, seen, kid, domain, tld)
            else:
                for kid, word in self.keyword_list:
                    if word in name_part:
                        self._emit(matches, seen, kid, domain, tld)

            if self._anchor_automaton is not None:
                for _, (anchor, pats) in self._anchor_automaton.iter(name_part):
                    for kid, rx in pats:
                        if kid not in seen and rx.search(name_part):
                            self._emit(matches, seen, kid, domain, tld)
            elif self._anchor_map:
                for anchor, pats in self._anchor_map.items():
                    if anchor in name_part:
                        for kid, rx in pats:
                            if kid not in seen and rx.search(name_part):
                                self._emit(matches, seen, kid, domain, tld)

            if include_anchorless:
                for kid, rx in self._anchorless:
                    if kid not in seen and rx.search(name_part):
                        self._emit(matches, seen, kid, domain, tld)

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
