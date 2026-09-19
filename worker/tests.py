#!/usr/bin/env python3
"""Simple unit tests for parser and matcher modules."""

import gzip
import os
import sqlite3
import tempfile

import parser
import matcher
import scheduler


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


def test_baseline_no_matches() -> None:
    # First scan of a TLD must cache the domains but not emit matches, otherwise
    # the whole zone floods the users as "new domains".
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE domains_cache (domain TEXT PRIMARY KEY, tld TEXT, first_seen TEXT);
        CREATE TABLE domains_cache_hash (domain_hash INTEGER PRIMARY KEY, tld TEXT, first_seen INTEGER) WITHOUT ROWID;
        CREATE TEMP TABLE zone_batch (domain TEXT PRIMARY KEY);
        CREATE TEMP TABLE zone_batch_hash (domain_hash INTEGER PRIMARY KEY);
    """)
    cursor = conn.cursor()
    keyword_matcher = matcher.Matcher([{"id": 1, "keyword": "santander"}])

    matches: list[dict] = []
    new_count = scheduler._stage_and_diff_batch(
        cursor, "xyz", "now", ["santander-bank.xyz"], keyword_matcher, matches,
        emit_matches=False,
    )
    assert new_count == 1, new_count
    assert matches == [], f"baseline must not emit matches: {matches}"
    assert conn.execute("SELECT COUNT(*) FROM domains_cache").fetchone()[0] == 1

    # A later scan only reports the genuinely new delegation.
    matches = []
    new_count = scheduler._stage_and_diff_batch(
        cursor, "xyz", "later", ["santander-bank.xyz", "santander-new.xyz"],
        keyword_matcher, matches, emit_matches=True,
    )
    assert new_count == 1, new_count
    assert len(matches) == 1 and matches[0]["domain"] == "santander-new.xyz", matches
    print("[PASS] test_baseline_no_matches")


def test_baseline_decision() -> None:
    # Never scanned -> baseline.
    is_baseline, mode_changed, mode = scheduler._baseline_decision(
        {"baselined": 0, "cache_mode": None}, use_hash=False)
    assert is_baseline and not mode_changed and mode == "text", (is_baseline, mode_changed, mode)

    # Already baselined, same mode -> emit.
    is_baseline, mode_changed, mode = scheduler._baseline_decision(
        {"baselined": 1, "cache_mode": "text"}, use_hash=False)
    assert not is_baseline and not mode_changed, (is_baseline, mode_changed)

    # Baslined but cache mode changed (text -> hash) -> suppress this run.
    is_baseline, mode_changed, mode = scheduler._baseline_decision(
        {"baselined": 1, "cache_mode": "text"}, use_hash=True)
    assert not is_baseline and mode_changed and mode == "hash", (is_baseline, mode_changed, mode)

    # Legacy TLD with no recorded mode -> treat as same mode (emit).
    is_baseline, mode_changed, mode = scheduler._baseline_decision(
        {"baselined": 1, "cache_mode": None}, use_hash=False)
    assert not is_baseline and not mode_changed, (is_baseline, mode_changed)
    print("[PASS] test_baseline_decision")


def test_search_cached_domains() -> None:
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE domains_cache (domain TEXT PRIMARY KEY, tld TEXT, first_seen TEXT);
        CREATE TABLE domains_cache_hash (domain_hash INTEGER PRIMARY KEY, tld TEXT, first_seen INTEGER) WITHOUT ROWID;
    """)
    conn.execute("INSERT INTO domains_cache VALUES ('santander-bank.xyz','xyz','2026-01-01T00:00:00Z')")
    conn.execute("INSERT INTO domains_cache VALUES ('my-santander-login.zip','zip','2026-01-02T00:00:00Z')")
    big = "santander-big.com"
    conn.execute("INSERT INTO domains_cache_hash VALUES (?, 'com', ?)",
                 (scheduler._domain_hash(big), 1700000000))

    r = scheduler.search_cached_domains(conn, "santander-bank.xyz", "exact")
    assert len(r["results"]) == 1 and r["results"][0]["domain"] == "santander-bank.xyz", r

    # Exact search must also find hash-cached (huge) TLDs.
    r = scheduler.search_cached_domains(conn, big, "exact")
    assert len(r["results"]) == 1 and r["results"][0].get("hash_cached"), r

    r = scheduler.search_cached_domains(conn, "santander", "prefix")
    assert {x["domain"] for x in r["results"]} == {"santander-bank.xyz"}, r

    r = scheduler.search_cached_domains(conn, "santander", "contains")
    assert len(r["results"]) == 2, r

    r = scheduler.search_cached_domains(conn, "san", "contains")
    assert r["results"] == [] and "4 characters" in r["note"], r

    r = scheduler.search_cached_domains(conn, "nope.xyz", "exact")
    assert r["results"] == [], r
    conn.close()
    print("[PASS] test_search_cached_domains")


def test_tld_meta_baseline_persistence() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        scheduler.update_tld_meta(db, "xyz", "etag1", "lm1", "2026-01-01", "ok",
                                  baselined=1, cache_mode="text")
        meta = scheduler.get_tld_meta(db, "xyz")
        assert meta["baselined"] == 1, meta
        assert meta["cache_mode"] == "text", meta

        # Updating only the run date must preserve the baseline state.
        scheduler.update_tld_meta(db, "xyz", "etag1", "lm1", "2026-01-02", "ok")
        meta = scheduler.get_tld_meta(db, "xyz")
        assert meta["baselined"] == 1, meta
        assert meta["cache_mode"] == "text", meta
        db.close()
    print("[PASS] test_tld_meta_baseline_persistence")


if __name__ == "__main__":
    test_parser_basic()
    test_parser_origin_relative()
    test_parser_whitespace_continuation()
    test_parser_lowercase_rrtype()
    test_parser_mixed_case_rrtype()
    test_matcher_basic()
    test_matcher_case_insensitive()
    test_baseline_no_matches()
    test_baseline_decision()
    test_search_cached_domains()
    test_tld_meta_baseline_persistence()
    print("\nAll tests passed.")
