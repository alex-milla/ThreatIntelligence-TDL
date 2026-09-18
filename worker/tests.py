#!/usr/bin/env python3
"""Simple unit tests for parser and matcher modules."""

import gzip
import os
import tempfile

import parser
import matcher


def create_test_zone(filepath: str, records: list[str]) -> None:
    with gzip.open(filepath, "wt") as f:
        for line in records:
            f.write(line + "\n")


def test_parser_basic() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.zone.gz")
        create_test_zone(path, [
            "$ORIGIN xyz.",
            "$TTL 3600",
            "example.xyz. 3600 IN NS ns1.example.com.",
            "example.xyz. 3600 IN A 1.2.3.4",
            "test.xyz. 3600 IN NS ns1.test.com.",
            "sub.test.xyz. 3600 IN NS ns1.sub.test.com.",
            "; comment line",
            "",
        ])
        domains = list(parser.parse_zone_gz(path, "xyz"))
        assert "example.xyz" in domains, f"example.xyz missing: {domains}"
        assert "test.xyz" in domains, f"test.xyz missing: {domains}"
        # Only SLDs directly under the TLD are kept (v1.3.8 behavior).
        assert "sub.test.xyz" not in domains, f"sub.test.xyz should be excluded: {domains}"
        print("[PASS] test_parser_basic")


def test_parser_origin_relative() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.zone.gz")
        create_test_zone(path, [
            "$ORIGIN zip.",
            "domain1 3600 IN NS ns1.example.com.",
            "domain2.zip. 3600 IN NS ns1.example.com.",
        ])
        domains = list(parser.parse_zone_gz(path, "zip"))
        assert "domain1.zip" in domains, f"domain1.zip missing: {domains}"
        assert "domain2.zip" in domains, f"domain2.zip missing: {domains}"
        print("[PASS] test_parser_origin_relative")


def test_parser_whitespace_continuation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.zone.gz")
        create_test_zone(path, [
            "$ORIGIN xyz.",
            "example.xyz. 3600 IN NS ns1.example.com.",
            "             3600 IN NS ns2.example.com.",
            "             3600 IN A 1.2.3.4",
            "other.xyz.   3600 IN NS ns1.other.com.",
        ])
        domains = list(parser.parse_zone_gz(path, "xyz"))
        # Should capture example.xyz and other.xyz
        # The A record line starts with whitespace but has no NS, so ignored
        assert "example.xyz" in domains, f"example.xyz missing: {domains}"
        assert "other.xyz" in domains, f"other.xyz missing: {domains}"
        assert domains.count("example.xyz") == 1, f"example.xyz duplicated: {domains}"
        print("[PASS] test_parser_whitespace_continuation")


def test_parser_lowercase_rrtype() -> None:
    # CZDS zone files use lowercase rrtypes ("in ns"). Regression test for the
    # case-sensitive byte pre-filter that dropped every NS line.
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.zone.gz")
        create_test_zone(path, [
            "$ORIGIN sbs.",
            "sbs.\t900\tin\tsoa\tns0.example.net. hostmaster.example.net. 1 900 1800 604800 3600",
            "0-1-4-9-8-0-7.sbs.\t3600\tin\tns\tns1.dyna-ns.net.",
            "0-1-4-9-8-0-7.sbs.\t3600\tin\tns\tns2.dyna-ns.net.",
            "example.sbs.\t3600\tin\tns\tns1.example.com.",
        ])
        domains = list(parser.parse_zone_gz(path, "sbs"))
        assert "0-1-4-9-8-0-7.sbs" in domains, f"lowercase ns SLD missing: {domains}"
        assert "example.sbs" in domains, f"example.sbs missing: {domains}"
        assert domains.count("0-1-4-9-8-0-7.sbs") == 1, f"duplicated: {domains}"
        print("[PASS] test_parser_lowercase_rrtype")


def test_parser_mixed_case_rrtype() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.zone.gz")
        create_test_zone(path, [
            "$ORIGIN xyz.",
            "a.xyz.\t3600\tIN\tNS\tns1.example.com.",
            "b.xyz.\t3600\tin\tns\tns1.example.com.",
            "c.xyz.\t3600\tIn\tNs\tns1.example.com.",
        ])
        domains = list(parser.parse_zone_gz(path, "xyz"))
        for expected in ("a.xyz", "b.xyz", "c.xyz"):
            assert expected in domains, f"{expected} missing: {domains}"
        print("[PASS] test_parser_mixed_case_rrtype")


def test_matcher_basic() -> None:
    keywords = [
        {"id": 1, "keyword": "santander"},
        {"id": 2, "keyword": "nasa"},
    ]
    domains = [
        "santander-bank.xyz",
        "nasa-gov.space",
        "random-domain.com",
        "my-santander-login.zip",
    ]
    matches = matcher.match_domains(domains, keywords)
    assert len(matches) == 3, f"Expected 3 matches, got {len(matches)}: {matches}"

    domains_found = {m["domain"] for m in matches}
    assert "santander-bank.xyz" in domains_found
    assert "nasa-gov.space" in domains_found
    assert "my-santander-login.zip" in domains_found
    assert "random-domain.com" not in domains_found
    print("[PASS] test_matcher_basic")


def test_matcher_case_insensitive() -> None:
    keywords = [{"id": 1, "keyword": "NASA"}]
    domains = ["nasa-test.xyz", "NASA-TEST.space", "Nasa-Org.com"]
    matches = matcher.match_domains(domains, keywords)
    assert len(matches) == 3, f"Expected 3 matches, got {len(matches)}"
    print("[PASS] test_matcher_case_insensitive")


if __name__ == "__main__":
    test_parser_basic()
    test_parser_origin_relative()
    test_parser_whitespace_continuation()
    test_parser_lowercase_rrtype()
    test_parser_mixed_case_rrtype()
    test_matcher_basic()
    test_matcher_case_insensitive()
    print("\nAll tests passed.")
