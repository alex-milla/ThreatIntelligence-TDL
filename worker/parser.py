#!/usr/bin/env python3
"""Streaming BIND zone file parser. Extracts delegated domains via NS records."""

import gzip


def parse_zone_gz(filepath: str, tld: str):
    """
    Yield unique domain names found in a gzip-compressed zone file.
    Only NS records are considered because they indicate delegation.

    The file is read as bytes and lines that cannot contain an NS record are
    skipped before decoding/tokenising, which speeds up large zone files
    considerably (the NS type is always preceded by whitespace).
    """
    origin = tld.lower().strip()
    if not origin.endswith("."):
        origin = origin + "."

    # We only want Second-Level Domains (SLDs) directly under this TLD.
    # For a TLD like "digital" we expect 2 labels (example.digital).
    # For a TLD like "co.uk" we expect 3 labels (example.co.uk).
    expected_labels = len(tld.lower().strip().rstrip(".").split(".")) + 1

    # Deduplicate consecutive identical owners only. Zone files list all RRs for
    # an owner together, so this catches the common duplicates in O(1) memory
    # instead of keeping every domain of a huge zone (e.g. .com) in a set.
    # Non-consecutive duplicates are removed later by the SQL staging table.
    last_yielded = None
    current_owner = origin

    with gzip.open(filepath, "rb") as fh:
        for raw in fh:
            # Directives ($ORIGIN, $TTL...) must be tracked before the filter.
            if raw[:1] == b"$":
                parts = raw.decode("utf-8", "ignore").strip().split(None, 1)
                if len(parts) >= 2 and parts[0].upper() == "$ORIGIN":
                    origin = parts[1].strip().lower()
                    if not origin.endswith("."):
                        origin += "."
                    current_owner = origin
                continue

            # Cheap byte-level pre-filter: skip lines with no NS-type token.
            if b" NS" not in raw and b"\tNS" not in raw:
                continue

            line = raw.decode("utf-8", "ignore").rstrip("\n\r")
            if not line or line.startswith(";"):
                continue

            # Remove inline comments
            if ";" in line:
                line = line.split(";")[0].rstrip()
            if not line:
                continue

            # Determine if this line starts with whitespace (owner inherited)
            starts_with_space = raw[0] in (0x20, 0x09)

            tokens = line.split()
            # Determine record type by skipping owner (if present), TTL (numeric), and class (IN/CH/HS)
            type_candidates = []
            for idx, tok in enumerate(tokens):
                if idx == 0 and not starts_with_space:
                    continue  # skip owner
                if tok.isdigit():
                    continue  # skip TTL
                if tok.upper() in ("IN", "CH", "HS"):
                    continue  # skip class
                type_candidates.append(tok.upper())
                if len(type_candidates) >= 1:
                    break
            if not type_candidates or type_candidates[0] != "NS":
                continue

            if starts_with_space:
                owner = current_owner
            else:
                owner = tokens[0].lower()
                if owner == "@":
                    owner = origin
                elif not owner.endswith("."):
                    owner = owner + "." + origin
                current_owner = owner

            owner = owner.rstrip(".")

            # Filter: only keep SLDs directly under the TLD.
            # Exclude wildcards, TLD apex, and infrastructure subdomains.
            actual_labels = len(owner.split("."))
            if actual_labels != expected_labels:
                continue
            if '*' in owner:
                continue

            if owner != last_yielded:
                last_yielded = owner
                yield owner
