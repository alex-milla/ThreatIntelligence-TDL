#!/usr/bin/env python3
"""Simple unit tests for parser and matcher modules."""

import configparser
import gzip
import os
import sqlite3
import tempfile

import parser
import matcher
import scheduler
import openintel
import virustotal
import whois


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


def test_openintel_version_key() -> None:
    files = ["20260901_x.parquet.gz", "20260908_y.parquet.gz", "20260825_z.parquet.gz"]
    files.sort(key=openintel._version_key)
    assert files[0] == "20260825_z.parquet.gz" and files[-1] == "20260908_y.parquet.gz", files
    print("[PASS] test_openintel_version_key")


def test_openintel_parse_date() -> None:
    assert openintel._parse_date("2026-09-19T06:00:00Z") is not None
    assert openintel._parse_date("2026-09-19") is not None
    assert openintel._parse_date("") is None
    assert openintel._parse_date("not a date") is None
    print("[PASS] test_openintel_parse_date")


def test_openintel_resolve_latest() -> None:
    # Simulate the real OpenINTEL index: unencoded '=' links, a
    # 'tld=io' -> 'tld%3Dio/' redirect, and an extra day= level.
    base = "https://www.openintel.nl/download/domain-lists/cctlds"
    obj = "https://object.openintel.nl/seeseetld/lists"

    def fake_links(session, url, sleep):
        u = url.rstrip("/")
        if u == openintel.BASE_URL:
            return [f"{base}/tld=io", f"{base}/tld=fr"]
        if u.endswith("/tld=io") or u.endswith("/tld%3Dio"):
            return [f"{base}/tld=io/year=2026"]
        if u.endswith("/year=2026") or u.endswith("/year%3D2026"):
            return [f"{base}/tld=io/year=2026/month=09",
                    f"{base}/tld=io/year=2026/month=08"]
        if u.endswith("/month=09") or u.endswith("/month%3D09"):
            return [f"{base}/tld=io/year=2026/month=09/day=14",
                    f"{base}/tld=io/year=2026/month=09/day=07"]
        if u.endswith("/day=14"):
            return [f"{obj}/tld=io/year=2026/month=09/day=14/ccTLD-domain-names-list.io.2026-09-14.csv.gz"]
        if u.endswith("/day=07"):
            return [f"{obj}/tld=io/year=2026/month=09/day=07/ccTLD-domain-names-list.io.2026-09-07.csv.gz"]
        return []

    original = openintel._links
    openintel._links = fake_links
    try:
        latest = openintel.resolve_latest(None, "io", 0, 0)
        previous = openintel.resolve_latest(None, "io", 1, 0)
    finally:
        openintel._links = original
    assert latest["filename"] == "ccTLD-domain-names-list.io.2026-09-14.csv.gz", latest
    assert previous["filename"] == "ccTLD-domain-names-list.io.2026-09-07.csv.gz", previous
    print("[PASS] test_openintel_resolve_latest")


def test_search_cached_domains_with_cctld() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        db.execute("INSERT OR IGNORE INTO domains_cache (domain, tld, first_seen) "
                   "VALUES ('brand-example.com', 'com', '2026-01-01')")
        db.commit()

        oi_path = os.path.join(tmpdir, "openintel.db")
        oi = sqlite3.connect(oi_path)
        oi.execute("CREATE TABLE cctld_seen (domain TEXT PRIMARY KEY, tld TEXT NOT NULL, "
                   "first_seen TEXT NOT NULL) WITHOUT ROWID")
        oi.execute("INSERT INTO cctld_seen VALUES ('cibersecurity.io', 'io', '2026-01-01')")
        oi.commit()
        oi.close()

        r = scheduler.search_cached_domains(db, "cibersecurity.io", "exact", openintel_db_path=oi_path)
        assert any(x["domain"] == "cibersecurity.io" and x["source"] == "ct" for x in r["results"]), r

        r = scheduler.search_cached_domains(db, "brand-example.com", "exact", openintel_db_path=oi_path)
        assert any(x["domain"] == "brand-example.com" and x["source"] == "zone" for x in r["results"]), r

        r = scheduler.search_cached_domains(db, "cibersecurity", "contains", openintel_db_path=oi_path)
        assert any(x["domain"] == "cibersecurity.io" for x in r["results"]), r
        db.close()
    print("[PASS] test_search_cached_domains_with_cctld")


def test_virustotal_classify() -> None:
    cases = [
        ({"last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 50, "undetected": 10}, "tags": []}, "malicious"),
        ({"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 5, "undetected": 1}, "tags": ["DGA"]}, "dga"),
        ({"last_analysis_stats": {"malicious": 0, "suspicious": 2, "harmless": 1, "undetected": 0}, "tags": []}, "suspicious"),
        ({"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 3, "undetected": 2}, "tags": []}, "clean"),
        ({}, "clean"),
    ]
    for attrs, expected in cases:
        got = virustotal.classify(attrs)
        assert got["verdict"] == expected, (attrs, got)
    assert virustotal.classify({"last_analysis_stats": {"malicious": 1}, "tags": ["dga"]})["verdict"] == "malicious"
    print("[PASS] test_virustotal_classify")


def test_local_db_vt_usage() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        db.execute("INSERT OR REPLACE INTO vt_usage (day, count) VALUES ('2026-09-19', 3)")
        db.commit()
        assert db.execute("SELECT count FROM vt_usage WHERE day = '2026-09-19'").fetchone()[0] == 3
        db.close()
    print("[PASS] test_local_db_vt_usage")


def test_daily_schedule_resolution() -> None:
    # Defaults: enabled, 04:00.
    enabled, hour, minute, _tz = scheduler.resolve_daily_schedule(configparser.ConfigParser())
    assert enabled and hour == 4 and minute == 0, (enabled, hour, minute)

    cfg = configparser.ConfigParser()
    cfg["worker"] = {"auto_daily": "false", "daily_run_time": "6:30",
                     "daily_run_timezone": "Europe/Madrid"}
    enabled, hour, minute, _tz = scheduler.resolve_daily_schedule(cfg)
    assert not enabled and hour == 6 and minute == 30, (enabled, hour, minute)

    # Invalid time/tz must fall back to 04:00/UTC without raising.
    bad = configparser.ConfigParser()
    bad["worker"] = {"daily_run_time": "99:99", "daily_run_timezone": "Nowhere/Nope"}
    enabled, hour, minute, tz = scheduler.resolve_daily_schedule(bad)
    assert enabled and hour == 4 and minute == 0, (hour, minute)
    assert tz is not None
    print("[PASS] test_daily_schedule_resolution")


def test_daily_cycle_due() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        # 00:00 UTC is always already past, so the daily flag alone decides.
        cfg = configparser.ConfigParser()
        cfg["worker"] = {"daily_run_time": "00:00", "daily_run_timezone": "UTC"}

        due, today, _tz = scheduler.daily_cycle_due(cfg, db)
        assert due and today, (due, today)

        scheduler.set_daily_attempt(db, today)
        due, today2, _tz = scheduler.daily_cycle_due(cfg, db)
        assert not due and today2 == today, (due, today2)
        assert scheduler.get_daily_attempt(db) == today

        scheduler.set_daily_attempt(db, "1970-01-01")
        due, _today, _tz = scheduler.daily_cycle_due(cfg, db)
        assert due, due

        off = configparser.ConfigParser()
        off["worker"] = {"auto_daily": "false", "daily_run_time": "00:00"}
        due, _today, _tz = scheduler.daily_cycle_due(off, db)
        assert not due, due
        db.close()
    print("[PASS] test_daily_cycle_due")


def test_openintel_json_available() -> None:
    # Regression: report() uses json.dumps; a missing import left commands
    # stuck in 'running' silently.
    assert hasattr(openintel, "json"), "openintel must import json"
    openintel.json.dumps({"ok": True})
    print("[PASS] test_openintel_json_available")


def test_openintel_recheck_cached() -> None:
    sent: list[dict] = []
    orig_kw = openintel.sync_client.get_keywords
    orig_send = openintel.sync_client.send_matches
    openintel.sync_client.get_keywords = lambda host, key: [{"id": 1, "keyword": "brand"}]

    def fake_send(host, key, matches):
        sent.extend(matches)
        return True

    openintel.sync_client.send_matches = fake_send
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = openintel.init_db(os.path.join(tmpdir, "oi.db"))
            conn.executemany(
                "INSERT INTO cctld_seen (domain, tld, first_seen) VALUES (?, ?, ?)",
                [("brand-a.io", "io", "2026-01-01"), ("other.io", "io", "2026-01-01")])
            conn.commit()
            stats = openintel.recheck_cached(conn, ["io"], "https://host", "key", {})
            conn.close()
    finally:
        openintel.sync_client.get_keywords = orig_kw
        openintel.sync_client.send_matches = orig_send

    assert stats["domains_checked"] == 2 and stats["matches_found"] == 1, stats
    assert len(sent) == 1 and sent[0]["domain"] == "brand-a.io", sent
    assert sent[0]["is_historical"] == 1 and sent[0]["source"] == "ct", sent
    print("[PASS] test_openintel_recheck_cached")


def test_openintel_csv_gz_read() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "ccTLD-domain-names-list.io.2026-09-14.csv.gz")
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write("Alpha.IO\nbeta.io\n\ngamma.io,extra-column\n")
        assert list(openintel.read_domains(path)) == ["alpha.io", "beta.io", "gamma.io"]
    print("[PASS] test_openintel_csv_gz_read")


def test_openintel_baseline_and_diff() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = openintel.init_db(os.path.join(tmpdir, "oi.db"))
        keyword_matcher = matcher.Matcher([{"id": 1, "keyword": "brand"}])

        # First run: baseline, cache only.
        matches: list[dict] = []
        total, new = openintel.process_domains(
            conn, "io", iter(["brand-a.io", "other.io"]), False, keyword_matcher, matches)
        assert total == 2 and new == 2 and matches == [], (total, new, matches)
        openintel.record_run(conn, "io", "f1", "baselined", total, new)
        assert openintel.tld_baselined(conn, "io")

        # Second run: only the genuine new domain is emitted.
        matches = []
        total, new = openintel.process_domains(
            conn, "io", iter(["brand-a.io", "other.io", "brand-b.io"]),
            True, keyword_matcher, matches)
        assert total == 3 and new == 1, (total, new)
        assert len(matches) == 1 and matches[0]["domain"] == "brand-b.io", matches
        conn.close()
    print("[PASS] test_openintel_baseline_and_diff")


def test_whois_rdap_override() -> None:
    # Built-in override for RDAP servers missing from the IANA bootstrap.
    assert whois.get_rdap_base("de", tempfile.gettempdir()) == "https://rdap.denic.de/"
    assert whois.get_rdap_base("de", tempfile.gettempdir(),
                               overrides={"de": "https://example.test/rdap"}) == "https://example.test/rdap/"
    print("[PASS] test_whois_rdap_override")


def test_whois_restricted_tld() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        info = whois.lookup_domain("example.es", tmpdir, disabled_tlds=None)
        assert info["status"] == "unsupported", info
        assert info["creation_date"] is None
    print("[PASS] test_whois_restricted_tld")


def test_whois_parse_text() -> None:
    text = (
        "Domain: example.com\n"
        "Registrar: Example Registrar, Inc.\n"
        "Creation Date: 2020-01-02T03:04:05Z\n"
        "Registry Expiry Date: 2030-01-02T03:04:05Z\n"
        "Name Server: NS1.EXAMPLE.COM\n"
        "Name Server: ns2.example.com\n"
    )
    parsed = whois._parse_whois_text(text)
    assert parsed["registrar"] == "Example Registrar, Inc.", parsed
    assert parsed["creation_date"] == "2020-01-02T03:04:05Z", parsed
    assert "ns1.example.com" in parsed["name_servers"], parsed
    print("[PASS] test_whois_parse_text")


def test_whois_cfg_parsing() -> None:
    assert scheduler._parse_tld_map("de=https://rdap.denic.de/, fr=whois.nic.fr") == {
        "de": "https://rdap.denic.de/", "fr": "whois.nic.fr"
    }
    assert scheduler._parse_tld_set("ES, .de ,") == {"es", "de"}
    assert openintel._whois_cfg_bool("false", True) is False
    assert openintel._whois_cfg_bool("true", False) is True
    assert openintel._whois_cfg_bool(None, True) is True
    print("[PASS] test_whois_cfg_parsing")


def test_openintel_parquet_read() -> None:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        print("[SKIP] test_openintel_parquet_read (pyarrow not installed)")
        return
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "week.parquet")
        pq.write_table(pa.table({"domain": ["Brand-A.io", "other.io"]}), path)
        assert list(openintel.read_domains(path)) == ["brand-a.io", "other.io"]
    print("[PASS] test_openintel_parquet_read")


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
    test_openintel_version_key()
    test_openintel_parse_date()
    test_openintel_resolve_latest()
    test_openintel_csv_gz_read()
    test_search_cached_domains_with_cctld()
    test_virustotal_classify()
    test_local_db_vt_usage()
    test_daily_schedule_resolution()
    test_daily_cycle_due()
    test_openintel_json_available()
    test_openintel_recheck_cached()
    test_openintel_baseline_and_diff()
    test_whois_rdap_override()
    test_whois_restricted_tld()
    test_whois_parse_text()
    test_whois_cfg_parsing()
    test_openintel_parquet_read()
    print("\nAll tests passed.")
