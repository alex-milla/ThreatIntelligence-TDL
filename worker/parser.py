#!/usr/bin/env python3
"""Streaming BIND zone file parser. Extracts delegated domains via NS records."""

import gzip


def parse_zone_gz(filepath: str, tld: str):
    """
    Yield unique domain names found in a gzip-compressed zone file.
    Only NS records are considered because they indicate delegation.
    """
    origin = tld.lower().strip()
    if not origin.endswith("."):
        origin = origin + "."

    seen = set()
    current_owner = origin

    with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n\r")
            if not line:
                continue
            if line.startswith(";"):
                continue
            if line.startswith("$"):
                parts = line.split(None, 1)
                if len(parts) >= 2 and parts[0].upper() == "$ORIGIN":
                    origin = parts[1].strip().lower()
                    if not origin.endswith("."):
                        origin += "."
                    current_owner = origin
                continue

            # Remove inline comments
            if ";" in line:
                line = line.split(";")[0].rstrip()
            if not line:
                continue

            # Determine if this line starts with whitespace (owner inherited)
            starts_with_space = raw_line[0] in " \t"

            tokens = line.split()
            if "NS" not in tokens:
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
            if owner not in seen:
                seen.add(owner)
                yield owner
