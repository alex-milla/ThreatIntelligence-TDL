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
import abusech
import intel
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


def test_openintel_resolve_tlds_precedence() -> None:
    cfg = configparser.ConfigParser()
    cfg.add_section("openintel")
    cfg.set("openintel", "tlds", "io,de")
    args = type("Args", (), {"tlds": None})()

    original = openintel.sync_client.get_openintel_tlds
    try:
        # Web panel is the source of truth: active ccTLDs win over config.
        openintel.sync_client.get_openintel_tlds = lambda host, key: ["es", "fr"]
        assert openintel.resolve_tlds(cfg, args, None, "http://host", "key") == ["es", "fr"]

        # Panel empty/unreachable -> config.ini fallback.
        openintel.sync_client.get_openintel_tlds = lambda host, key: []
        assert openintel.resolve_tlds(cfg, args, None, "http://host", "key") == ["io", "de"]

        # Explicit --tlds wins over both.
        args.tlds = "io, es"
        assert openintel.resolve_tlds(cfg, args, None, "http://host", "key") == ["io", "es"]
    finally:
        openintel.sync_client.get_openintel_tlds = original
    print("[PASS] test_openintel_resolve_tlds_precedence")


def test_filter_keywords() -> None:
    kws = [{"id": 1, "keyword": "acme"}, {"id": 2, "keyword": "nasa"}, {"id": 3, "keyword": "globex"}]
    # None/empty = all keywords (no filter).
    assert matcher.filter_keywords(kws, None) == kws
    assert matcher.filter_keywords(kws, []) == kws
    # Subset, including string ids, keeps only the wanted ones.
    assert [k["id"] for k in matcher.filter_keywords(kws, [2])] == [2]
    assert [k["id"] for k in matcher.filter_keywords(kws, ["1", 3])] == [1, 3]
    # Unknown/blank ids do not match anything.
    assert matcher.filter_keywords(kws, [99]) == []
    print("[PASS] test_filter_keywords")


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


def test_abusech_classify() -> None:
    uh = {
        "query_status": "ok",
        "url_count": "3",
        "firstseen": "2026-09-01 10:00:00 UTC",
        "blacklists": {"spamhaus_dbl": "phishing_domain", "surbl": "listed"},
        "urls": [
            {"url_status": "online", "tags": ["emotet", "exe"]},
            {"url_status": "offline", "tags": ["emotet"]},
        ],
    }
    tf_hit = {
        "query_status": "ok",
        "data": [{"threat_type": "botnet_cc", "ioc_type": "domain",
                  "malware_printable": "Dridex", "confidence_level": 75,
                  "first_seen": "2026-09-02 00:00:00 UTC", "last_seen": None,
                  "tags": ["exe"]}],
    }
    got = abusech.classify(uh, tf_hit)
    assert got["verdict"] == "malicious", got
    assert got["urlhaus_verdict"] == "malicious"
    assert got["urlhaus_online"] == 1
    assert got["urlhaus_dbl"] == "phishing_domain"
    assert got["threatfox_verdict"] == "malicious"
    assert got["threatfox_matches"] == 1
    assert got["malware_family"] == "Dridex"
    assert got["threat_type"] == "botnet_cc"
    assert "emotet" in got["tags"] and "exe" in got["tags"]
    assert got["last_analysis_date"] == "2026-09-02 00:00:00 UTC"

    # URLhaus offline + spammer DBL, no ThreatFox -> suspicious.
    uh2 = {"query_status": "ok", "url_count": "2",
           "blacklists": {"spamhaus_dbl": "spammer_domain"}, "urls": []}
    assert abusech.classify(uh2, {"query_status": "no_results"})["verdict"] == "suspicious"

    # URLhaus found but offline / not listed -> suspicious (it tracks malware URLs).
    uh3 = {"query_status": "ok", "url_count": "1",
           "blacklists": {"spamhaus_dbl": "not listed"},
           "urls": [{"url_status": "offline", "tags": []}]}
    assert abusech.classify(uh3, {"query_status": "no_results"})["verdict"] == "suspicious"

    # Not found anywhere -> clean.
    assert abusech.classify({"query_status": "no_results"}, {"query_status": "no_results"})["verdict"] == "clean"
    assert abusech.classify({}, {})["verdict"] == "clean"
    # ThreatFox returns no_result (singular) with a string data payload.
    assert abusech.classify({"query_status": "no_results"},
                            {"query_status": "no_result", "data": "Your search did not yield any results"})["verdict"] == "clean"
    print("[PASS] test_abusech_classify")


def test_abusech_errors() -> None:
    assert abusech.is_auth_failure(401, "") is True
    assert abusech.is_auth_failure(403, '{"query_status": "unknown_auth_key"}') is True
    assert abusech.is_auth_failure(403, '{"query_status": "no_results"}') is False
    assert abusech.is_auth_failure(429, "quota") is False
    r = abusech.error_result("x.example", "urlhaus HTTP 403 authentication failed")
    assert r["status"] == "error" and r["domain"] == "x.example" and "auth" in r["error"]
    # Unexpected query_status is no longer treated as clean (pure classify stays
    # the same, but lookup_domain guards it; here we only assert the helpers).
    print("[PASS] test_abusech_errors")


def test_abusech_feed_parse() -> None:
    uh_csv = (
        "################################################################\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2026-09-01 10:00:00","http://evil.example/a.exe","online","2026-09-01 10:00:00","malware_download","emotet,exe","https://urlhaus.abuse.ch/url/1/","x"\n'
        '"2","2026-09-02 10:00:00","http://evil.example/b.exe","offline","","malware_download","None","https://urlhaus.abuse.ch/url/2/","y"\n'
        '"3","2026-09-03 10:00:00","http://1.2.3.4/payload","online","2026-09-03 10:00:00","malware_download","None","https://urlhaus.abuse.ch/url/3/","z"\n'
    )
    uh = abusech.parse_urlhaus_csv(uh_csv)
    assert "evil.example" in uh and "1.2.3.4" not in uh, uh
    assert uh["evil.example"]["url_count"] == 2
    assert uh["evil.example"]["online"] == 1
    assert "emotet" in uh["evil.example"]["tags"]

    tf_csv = (
        "########################\n"
        '"first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias", "malware_printable", "last_seen_utc", "confidence_level", "is_compromised", "reference", "tags", "anonymous", "reporter"\n'
        '"2026-09-01 00:00:00", "10", "bad.example", "domain", "botnet_cc", "win.dridex", "None", "Dridex", "", "75", "False", "None", "exe", "0", "abuse_ch"\n'
        '"2026-09-01 00:00:00", "11", "9.9.9.9:443", "ip:port", "botnet_cc", "win.dridex", "None", "Dridex", "", "75", "False", "None", "None", "0", "abuse_ch"\n'
        '"2026-09-01 00:00:00", "12", "http://url.example/x", "url", "payload", "win.x", "None", "X", "", "50", "False", "None", "None", "0", "abuse_ch"\n'
    )
    tf = abusech.parse_threatfox_csv(tf_csv)
    assert "bad.example" in tf and "url.example" not in tf, tf
    assert tf["bad.example"]["malware"] == "Dridex"
    assert tf["bad.example"]["threat_type"] == "botnet_cc"
    assert tf["bad.example"]["confidence"] == 75
    print("[PASS] test_abusech_feed_parse")


def test_abusech_feed_lookup() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        now = "2026-09-24 00:00:00"
        db.executemany(
            "INSERT INTO abusech_feed (domain, source, threat_type, malware, confidence, tags, "
            "first_seen, last_seen, url_count, online, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("evil.example", "urlhaus", "malware_download", "", 0, "emotet", "2026-09-01", None, 3, 1, now),
                ("bad.example", "threatfox", "botnet_cc", "Dridex", 75, "exe", "2026-09-01", None, 0, 0, now),
                ("offline.example", "urlhaus", "malware_download", "", 0, "", "2026-09-01", None, 2, 0, now),
            ])
        db.commit()
        got = {e["domain"]: e for e in abusech.feed_lookup(
            db, ["evil.example", "bad.example", "offline.example", "clean.example"])}
        assert got["evil.example"]["verdict"] == "malicious"
        assert got["evil.example"]["urlhaus_online"] == 1
        assert got["bad.example"]["verdict"] == "malicious"
        assert got["bad.example"]["malware_family"] == "Dridex"
        assert got["offline.example"]["verdict"] == "suspicious"
        assert "clean.example" not in got
        assert abusech.feed_age_hours(db) is None
        db.execute("INSERT OR REPLACE INTO abusech_feed_meta (key,value) VALUES ('synced_at','2026-09-24 00:00:00')")
        db.commit()
        age = abusech.feed_age_hours(db)
        assert age is not None and age >= 0
        db.close()
    print("[PASS] test_abusech_feed_lookup")


def test_intel_signals() -> None:
    base = {"whois": {"name_servers": '["ns1.park.example","ns2.park.example"]', "registrar": "Park Inc"}}
    changed, detail = intel.compare_whois(base, {"name_servers": ["ns1.host.example", "ns2.host.example"], "registrar": "Park Inc"})
    assert changed and "nameservers" in detail, (changed, detail)
    assert intel.compare_whois(base, {"name_servers": ["ns1.park.example", "ns2.park.example"], "registrar": "Park Inc"})[0] is False
    assert intel.compare_whois({}, {"name_servers": ["x"]})[0] is False
    assert intel.compare_whois(base, {"name_servers": ["ns1.park.example", "ns2.park.example"], "registrar": "Other Ltd"})[0] is True

    ev = intel.evaluate({"verdict": "suspicious"}, {"verdict": "clean"}, False)
    assert ev["activated"] and "abuse.ch" in ev["activated_reason"]
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "malicious"}, False)
    assert ev["activated"] and "VirusTotal" in ev["activated_reason"]
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, True, "nameservers changed")
    assert not ev["activated"] and ev["whois_changed"]
    assert any(s["type"] == "whois_change" for s in ev["signals"])

    # F2: DNS starts resolving / a new TLS certificate activate the entry.
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, dns_started=True, dns_now=True)
    assert ev["activated"] and "DNS" in ev["activated_reason"], ev
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, cert_new=True)
    assert ev["activated"] and "certificate" in ev["activated_reason"], ev
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, dns_started=False, dns_now=False)
    assert not ev["activated"] and any(s["type"] == "dns" for s in ev["signals"])

    certs = [{"not_before": "2026-08-01T00:00:00"}, {"not_before": "2026-09-20T10:00:00"}]
    assert intel.cert_newer_than(certs, "2026-09-10 00:00:00") is True
    assert intel.cert_newer_than(certs, "2026-09-25 00:00:00") is False
    assert intel.cert_newer_than([], "2026-09-10 00:00:00") is False
    assert intel.cert_newer_than([{"entry_timestamp": "2026-09-21 08:00:00"}], "2026-09-10 00:00:00") is True

    # F3: HTTP helpers and activation.
    html = "<html><head><title>Acme Login</title></head><body><form><input type='password' name='p'></form></body></html>"
    assert intel.has_login_form(html) is True
    assert intel.has_login_form("<p>no form</p>") is False
    assert intel.extract_title(html) == "Acme Login"
    assert intel.contains_keyword("Acme Login", html, ["acme"]) is True
    assert intel.contains_keyword("Other", "nothing", ["acme"]) is False
    h1 = intel.content_hash(html)
    assert h1 and h1 == intel.content_hash(html) and h1 != intel.content_hash(html + "x")
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, http_brand=True, http_200=200)
    assert ev["activated"] and "brand content" in ev["activated_reason"], ev
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, http_login=True, http_200=200)
    assert ev["activated"] and "login form" in ev["activated_reason"], ev
    ev = intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, http_200=True, http_activate_any_200=True)
    assert ev["activated"] and "responds 200" in ev["activated_reason"], ev
    assert not intel.evaluate({"verdict": "clean"}, {"verdict": "clean"}, False, http_200=200)["activated"]
    print("[PASS] test_intel_signals")


def test_weekly_tracking_schedule() -> None:
    cfg = configparser.ConfigParser()
    cfg["tracking"] = {"weekly_enabled": "true", "weekly_day": "sunday",
                       "weekly_run_time": "03:00", "weekly_run_timezone": "UTC"}
    enabled, weekday, hour, minute, _tz = scheduler.resolve_weekly_schedule(cfg)
    assert enabled and weekday == 6 and hour == 3 and minute == 0, (enabled, weekday, hour, minute)

    bad = configparser.ConfigParser()
    bad["tracking"] = {"weekly_enabled": "true", "weekly_day": "nope", "weekly_run_time": "99:99"}
    enabled, weekday, hour, minute, _tz = scheduler.resolve_weekly_schedule(bad)
    assert weekday == 6 and hour == 3 and minute == 0, (weekday, hour, minute)

    disabled = configparser.ConfigParser()
    disabled["tracking"] = {"weekly_enabled": "false"}
    assert scheduler.resolve_weekly_schedule(disabled)[0] is False

    import datetime as _dt

    class _FakeDateTime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime(2026, 9, 27, 3, 30, tzinfo=tz)

    expected_key = _dt.datetime(2026, 9, 27).strftime("%G-W%V")
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        orig = scheduler.datetime
        scheduler.datetime = _FakeDateTime
        try:
            due, week_key, _tz = scheduler.weekly_tracking_due(cfg, db)
            assert due and week_key == expected_key, (due, week_key, expected_key)
            scheduler.set_weekly_attempt(db, week_key)
            assert scheduler.weekly_tracking_due(cfg, db)[0] is False
        finally:
            scheduler.datetime = orig
        db.close()
    print("[PASS] test_weekly_tracking_schedule")


def test_glob_matching() -> None:
    # glob -> regex + anchor extraction
    rx, anchor = matcher.glob_to_regex("micro*soft")
    assert anchor == "micro", anchor
    assert rx.search("micro-soft") and rx.search("microsoft")

    rx, _ = matcher.glob_to_regex("pay?al")
    assert rx.search("paypal") and rx.search("payxal") and not rx.search("payal")

    rx, anchor = matcher.glob_to_regex("microsoft[0-9]")
    assert anchor == "microsoft", anchor
    assert rx.search("microsoft5") and not rx.search("microsoftx")

    rx, _ = matcher.glob_to_regex("[0-9]{2,4}juegos")
    assert rx.search("123juegos") and not rx.search("1juegos")

    # Matcher: every keyword is matched literally, and as a glob when it has
    # wildcards (no type is configured).
    kws = [
        {"id": 1, "keyword": "santander"},
        {"id": 2, "keyword": "micro*soft"},
        {"id": 3, "keyword": "[0-9]{3}[a-z]{0,2}"},  # no anchor
    ]
    m = matcher.Matcher(kws)
    got = {(x["keyword_id"], x["domain"]) for x in m.match(
        ["santander-bank.xyz", "micro-soft.com", "123.xyz", "nope.com"])}
    assert (1, "santander-bank.xyz") in got, got
    assert (2, "micro-soft.com") in got, got
    assert (3, "123.xyz") in got, got

    # Recheck (for_recheck) skips anchorless patterns but keeps anchored ones.
    mr = matcher.Matcher(kws, for_recheck=True)
    gotr = {x["keyword_id"] for x in mr.match(["santander-bank.xyz", "micro-soft.com", "123.xyz"])}
    assert 1 in gotr and 2 in gotr and 3 not in gotr, gotr
    print("[PASS] test_glob_matching")


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


def test_auto_whois_helpers() -> None:
    cfg = configparser.ConfigParser()
    cfg["worker"] = {"auto_whois": "false", "auto_whois_max": "200",
                     "data_dir": tempfile.gettempdir()}
    matches = [
        {"domain": "Brand-A.io", "is_historical": 0},
        {"domain": "brand-a.io", "is_historical": 0},
        {"domain": "old.io", "is_historical": 1},
        {"domain": "brand-b.io", "is_historical": 0},
    ]
    # Disabled by config: no lookups.
    assert scheduler.auto_whois_new_matches(cfg, "http://x", "k", matches) == 0

    cfg.set("worker", "auto_whois", "true")
    captured = {}

    def fake_entries(_cfg, _data_dir, domains):
        captured["domains"] = list(domains)
        return [{"domain": d, "status": "ok"} for d in domains]

    orig_entries = scheduler.whois_lookup_entries
    orig_send = scheduler.sync_client.send_whois_results
    try:
        scheduler.whois_lookup_entries = fake_entries
        scheduler.sync_client.send_whois_results = lambda *a, **k: True

        # Deduplicated, historical skipped.
        cfg.set("worker", "auto_whois_max", "10")
        assert scheduler.auto_whois_new_matches(cfg, "http://x", "k", matches) == 2
        assert captured["domains"] == ["brand-a.io", "brand-b.io"], captured

        # Capped.
        cfg.set("worker", "auto_whois_max", "1")
        assert scheduler.auto_whois_new_matches(cfg, "http://x", "k", matches) == 1
        assert captured["domains"] == ["brand-a.io"], captured

        # Cap 0 disables it.
        cfg.set("worker", "auto_whois_max", "0")
        assert scheduler.auto_whois_new_matches(cfg, "http://x", "k", matches) == 0
    finally:
        scheduler.whois_lookup_entries = orig_entries
        scheduler.sync_client.send_whois_results = orig_send
    print("[PASS] test_auto_whois_helpers")


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


def test_icann_auth_error_reporting() -> None:
    import downloader

    class FakeResp:
        def __init__(self, status_code, text="", data=None):
            self.status_code = status_code
            self.text = text
            self._data = data or {}

        def json(self):
            return self._data

    orig_post = downloader.requests.post
    orig_get = downloader.requests.get
    try:
        downloader.requests.post = lambda *a, **k: FakeResp(401, '{"error":"invalid_grant"}')
        token, err = downloader.get_token("u", "p")
        assert token is None and err is not None, (token, err)
        assert "401" in err and "invalid_grant" in err, err

        downloader.requests.post = lambda *a, **k: FakeResp(200, "", {"accessToken": "tok"})
        token, err = downloader.get_token("u", "p")
        assert token == "tok" and err is None, (token, err)

        downloader.requests.get = lambda *a, **k: FakeResp(500, "server error")
        tlds, gerr = downloader.get_approved_tlds("tok")
        assert tlds == [] and gerr is not None and "500" in gerr, (tlds, gerr)
    finally:
        downloader.requests.post = orig_post
        downloader.requests.get = orig_get
    print("[PASS] test_icann_auth_error_reporting")


def test_icann_failure_report() -> None:
    captured = {}

    orig_get_active = scheduler.sync_client.get_active_tlds
    orig_report = scheduler.sync_client.report_tld_sync
    orig_logs = scheduler.sync_client.send_logs

    def fake_get_active(host, key):
        return ["com", "net"]

    def fake_report(host, key, entries):
        captured["entries"] = entries
        return True

    def fake_logs(host, key, logs):
        captured["logs"] = logs
        return True

    scheduler.sync_client.get_active_tlds = fake_get_active
    scheduler.sync_client.report_tld_sync = fake_report
    scheduler.sync_client.send_logs = fake_logs
    try:
        entries = scheduler.report_icann_failure("http://h", "k", "auth", "HTTP 401")
    finally:
        scheduler.sync_client.get_active_tlds = orig_get_active
        scheduler.sync_client.report_tld_sync = orig_report
        scheduler.sync_client.send_logs = orig_logs

    assert captured["logs"][0]["level"] == "error"
    assert "auth" in captured["logs"][0]["message"]
    assert {e["tld"] for e in entries} == {"com", "net"}
    assert all(e["status"] == "failed" for e in entries)
    assert all("ICANN cycle aborted" in e["error"] for e in entries)

    summary = scheduler._cycle_summary_log({"error": "HTTP 401", "stage": "auth"}, "Worker cycle")
    assert summary["level"] == "error" and "auth" in summary["message"]
    ok_summary = scheduler._cycle_summary_log(
        {"tlds_processed": 3, "matches_found": 5}, "Worker cycle")
    assert ok_summary["level"] == "info" and "3 TLDs" in ok_summary["message"]
    print("[PASS] test_icann_failure_report")


def test_glob_search_cached_domains() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        db.executemany(
            "INSERT INTO domains_cache (domain, tld, first_seen) VALUES (?, ?, ?)",
            [
                ("bancosantander.com", "com", "2026-09-25T00:00:00+00:00"),
                ("banco-santander.com", "com", "2026-09-01T00:00:00+00:00"),
                ("banco12santander.com", "com", "2026-08-15T00:00:00+00:00"),
                ("santander-x.net", "net", "2026-09-25T00:00:00+00:00"),
                ("otrositio.org", "org", "2026-01-01T00:00:00+00:00"),
            ])
        db.commit()

        # Fast path: SQLite GLOB, unanchored '*' (matches anywhere in the domain).
        res = scheduler.search_cached_domains(db, "banco*santander", mode="glob")
        got = {r["domain"] for r in res["results"]}
        assert "bancosantander.com" in got and "banco-santander.com" in got, got
        assert "banco12santander.com" in got, got
        assert "santander-x.net" not in got and "otrositio.org" not in got, got

        # Discovery-date window (inclusive) narrows the results.
        res = scheduler.search_cached_domains(db, "banco*santander", mode="glob",
                                              after="2026-09-01", before="2026-09-30")
        got = {r["domain"] for r in res["results"]}
        assert got == {"bancosantander.com", "banco-santander.com"}, got

        res = scheduler.search_cached_domains(db, "banco*santander", mode="glob",
                                              after="2026-09-25", before="2026-09-25")
        got = {r["domain"] for r in res["results"]}
        assert got == {"bancosantander.com"}, got

        res = scheduler.search_cached_domains(db, "banco*santander", mode="glob",
                                              after="2026-08-01", before="2026-08-31")
        got = {r["domain"] for r in res["results"]}
        assert got == {"banco12santander.com"}, got

        # Negated class translated to SQLite '^' negation: exactly one non-digit
        # between "banco" and "santander", so only the hyphenated domain matches.
        res = scheduler.search_cached_domains(db, "banco[!0-9]santander", mode="glob")
        got = {r["domain"] for r in res["results"]}
        assert got == {"banco-santander.com"}, got

        # {n,m} repetition: regex fallback with full parity (and the date filter
        # also applies on that path).
        res = scheduler.search_cached_domains(db, "banco[0-9]{2}santander", mode="glob")
        got = {r["domain"] for r in res["results"]}
        assert got == {"banco12santander.com"}, got

        res = scheduler.search_cached_domains(db, "banco[0-9]{2}santander", mode="glob",
                                              after="2026-09-01", before="2026-09-30")
        assert res["results"] == [], res

        # No usable anchor: rejected without scanning.
        res = scheduler.search_cached_domains(db, "*", mode="glob")
        assert res["results"] == [], res
        assert "literal" in res["note"].lower(), res

        # glob_to_sqlite translation unit checks.
        assert matcher.glob_to_sqlite("banco*santander") == "banco*santander"
        assert matcher.glob_to_sqlite("banco[!0-9]santander") == "banco[^0-9]santander"
        assert matcher.glob_to_sqlite("banco[0-9]{2}") is None
        db.close()
    print("[PASS] test_glob_search_cached_domains")


def test_cloudflare_radar_classify() -> None:
    import cloudflare_radar as cf

    report = {
        "task": {"success": True, "status": "Finished", "time": "2026-09-25T10:00:00Z", "url": "https://evil.example"},
        "verdicts": {"overall": {"malicious": True}},
        "page": {"asn": "AS13335", "country": "United States", "ip": "1.2.3.4",
                 "domStructHash": "abc123", "favicon": {"hash": "def456"}},
        "lists": {"certificates": [{"issuer": "Let's Encrypt"}]},
        "meta": {"processors": {
            "domainCategories": ["Phishing", "Newly Seen Domains"],
            "phishing": ["Credential Harvester"],
            "radarRank": "123456",
            "wappa": [{"name": "WordPress"}, {"name": "PHP"}],
        }},
    }
    out = cf.classify(report, "evil.example", "https://radar.cloudflare.com/scan/x")
    assert out["status"] == "ok", out
    assert out["verdict"] == "malicious", out
    assert "Phishing" in out["categories"], out
    assert "Credential Harvester" in out["phishing"], out
    assert out["radar_rank"] == "123456", out
    assert "WordPress" in out["technologies"] and "PHP" in out["technologies"], out
    assert out["asn"] == "AS13335" and out["country"] == "United States", out
    assert out["cert_issuer"] == "Let's Encrypt", out
    assert out["report_url"].endswith("/scan/x"), out

    # Real Cloudflare shape: every processor is {"data": [...]}.
    nested = {
        "task": {"success": True, "status": "Finished"},
        "verdicts": {"overall": {}},
        "page": {"asn": "AS123", "country": "Spain"},
        "meta": {"processors": {
            "domainCategories": {"data": [
                {"name": "Newly Seen Domains", "isPrimary": False, "inherited": False},
                {"name": "Financial Services", "isPrimary": True, "inherited": False},
            ]},
            "phishing": {"data": []},
            "radarRank": {"data": [
                {"hostname": "cdn.example", "rank": 900, "bucket": "top_1000"},
                {"hostname": "mediolanum.website", "rank": 42517, "bucket": "top_50000"},
            ]},
            "wappa": {"data": [
                {"app": "WordPress"},
                {"app": "PHP", "categories": [{"name": "Programming languages", "priority": 1}]},
            ]},
        }},
    }
    got = cf.classify(nested, "mediolanum.website")
    assert got["radar_rank"] == "42517", got
    assert got["categories"] == "Financial Services, Newly Seen Domains", got
    assert "WordPress" in got["technologies"] and "PHP" in got["technologies"], got
    assert got["phishing"] == "", got

    # Malformed (stringified dict / bare "data") processor values are dropped.
    malformed = {
        "task": {"success": True},
        "verdicts": {"overall": {}},
        "meta": {"processors": {
            "domainCategories": ["{'data': [{'name': 'Phishing'}]}"],
            "phishing": ["data"],
            "radarRank": "{'data': [{'hostname': 'x', 'rank': 1}]}",
            "wappa": [{"app": "data"}],
        }},
    }
    bad = cf.classify(malformed, "x.example")
    assert bad["categories"] == "", bad
    assert bad["phishing"] == "", bad
    assert bad["radar_rank"] == "", bad
    assert bad["technologies"] == "", bad
    assert bad["verdict"] == "clean", bad

    # A clean page (no malicious verdict, benign category) -> clean.
    clean = cf.classify({"task": {"success": True}, "verdicts": {"overall": {}},
                         "meta": {"processors": {"domainCategories": ["Technology"]}}}, "ok.example")
    assert clean["verdict"] == "clean", clean

    # A failed scan records an error and no verdict.
    failed = cf.classify({"task": {"success": False, "status": "Failed"}}, "bad.example")
    assert failed["status"] == "error" and failed["verdict"] == "", failed

    # error_result is storable.
    er = cf.error_result("x.example", "boom")
    assert er["status"] == "error" and er["domain"] == "x.example", er
    print("[PASS] test_cloudflare_radar_classify")


def test_cloudflare_radar_errors() -> None:
    import cloudflare_radar as cf

    class FakeResp:
        def __init__(self, status_code, data=None):
            self.status_code = status_code
            self._data = data or {}

        def json(self):
            return self._data

    orig_post = cf.requests.post
    orig_get = cf.requests.get
    try:
        cf.requests.post = lambda *a, **k: FakeResp(401)
        try:
            cf.scan_domain("x.example", "tok", "acct")
            assert False, "expected AuthError"
        except cf.AuthError:
            pass

        cf.requests.get = lambda *a, **k: FakeResp(429)
        try:
            cf.dns_top_locations("x.example", "tok")
            assert False, "expected QuotaError"
        except cf.QuotaError:
            pass

        # Missing configuration is an AuthError, not a crash.
        try:
            cf.scan_domain("x.example", "", "")
            assert False, "expected AuthError"
        except cf.AuthError:
            pass
    finally:
        cf.requests.post = orig_post
        cf.requests.get = orig_get
    print("[PASS] test_cloudflare_radar_errors")


def test_cloudflare_dns_batch() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        cfg = configparser.ConfigParser()
        cfg.add_section("cloudflare")
        cfg.set("cloudflare", "radar_enabled", "true")
        cfg.set("cloudflare", "api_token", "tok")
        cfg.set("cloudflare", "rate_delay_seconds", "10 ; inline comment")
        cfg.set("cloudflare", "urlscanner_token", "; empty")
        cfg.set("cloudflare", "dns_rate_delay_seconds", "0")

        # The hardened reader strips inline comments and falls back to api_token.
        cf = scheduler._cf_config(cfg)
        assert cf["rate_delay"] == 10.0, cf
        assert cf["urlscanner_token"] == "tok", cf

        captured = []
        reported = []
        orig_dns = scheduler.cloudflare_radar.dns_top_locations
        orig_send = scheduler.sync_client.send_cfscan_results
        orig_usage = scheduler.sync_client.send_api_usage

        def fake_dns(d, tok, timeout=30, limit=10, usage=None):
            if usage is not None:
                usage["calls"] = int(usage.get("calls", 0)) + 1
            return [{"code": "ES", "name": "Spain", "value": "80.0"}]

        scheduler.cloudflare_radar.dns_top_locations = fake_dns
        scheduler.sync_client.send_cfscan_results = lambda h, k, e: captured.extend(e) or True
        scheduler.sync_client.send_api_usage = lambda h, k, p: reported.append(p) or True
        try:
            stats = scheduler.run_cfdns_batch(cfg, db, "http://h", "k", ["a.example", "b.example"])
        finally:
            scheduler.cloudflare_radar.dns_top_locations = orig_dns
            scheduler.sync_client.send_cfscan_results = orig_send
            scheduler.sync_client.send_api_usage = orig_usage

        assert stats["checked"] == 2, stats
        assert len(captured) == 2 and all(e.get("dns_only") for e in captured), captured
        assert captured[0]["dns_countries"][0]["code"] == "ES", captured
        # The (cheap) Radar calls are reported so the Admin panel shows the usage.
        assert reported, reported
        day_key, _ = scheduler._cf_periods()
        calls = {row["period"]: row for row in reported[0]["usage"]}
        assert calls["calls:" + day_key]["count"] == 2, reported
        db.close()
    print("[PASS] test_cloudflare_dns_batch")


def test_cloudflare_usage_headers() -> None:
    import cloudflare_radar as cf
    import scheduler

    class FakeResp:
        def __init__(self, status_code=200, headers=None):
            self.status_code = status_code
            self.headers = headers or {}
            self._data = {}

        def json(self):
            return self._data

    info = cf.parse_ratelimit_headers(FakeResp(200, {
        "Ratelimit": '"default";r=50;t=30',
        "Ratelimit-Policy": '"burst";q=100;w=60',
    }))
    assert info["remaining"] == 50 and info["reset_seconds"] == 30, info
    assert info["quota"] == 100 and info["window_seconds"] == 60, info
    assert info["ratelimit"].endswith("r=50;t=30"), info

    # Empty / malformed headers never crash and yield no numeric fields.
    assert "remaining" not in cf.parse_ratelimit_headers(
        FakeResp(200, {"Ratelimit": "garbage"})), "garbage"
    assert cf.parse_ratelimit_headers(FakeResp(200, {})) == {}, "empty"

    usage = {"calls": 0}
    cf._note_call(usage, FakeResp(200, {"Ratelimit": '"default";r=50;t=30'}))
    cf._note_call(usage, FakeResp(429, {"Retry-After": "120"}))
    assert usage["calls"] == 2, usage
    assert usage["last"]["remaining"] == 50, usage          # merged, not lost
    assert usage["last"]["retry_after"] == "120", usage
    assert usage.get("rate_limited") is True, usage
    # A following success clears the stale Retry-After.
    cf._note_call(usage, FakeResp(200, {"Ratelimit": '"default";r=49;t=29'}))
    assert "retry_after" not in usage["last"], usage
    assert usage["last"]["remaining"] == 49, usage

    with tempfile.TemporaryDirectory() as tmpdir:
        db = scheduler.init_local_db(os.path.join(tmpdir, "worker.db"))
        cfg = configparser.ConfigParser()
        cfg.add_section("cloudflare")
        cfg.set("cloudflare", "urlscanner_token", "tok")
        cfg.set("cloudflare", "account_id", "acct")
        cfg.set("cloudflare", "daily_limit", "150")
        cfg.set("cloudflare", "monthly_limit", "5000")

        scheduler._cf_record_usage(db, {"calls": 3, "last": {"remaining": 50}, "rate_limited": True})
        snap = scheduler.cf_usage_snapshot(db, cfg)
        assert snap["calls"]["day"] == 3 and snap["calls"]["month"] == 3, snap
        assert snap["scans"]["daily_limit"] == 150 and snap["scans"]["monthly_limit"] == 5000, snap
        assert snap["meta"]["remaining"] == 50, snap
        assert snap["meta"]["rate_limited"] == "1", snap

        payload = scheduler._cf_usage_payload(db, cfg)
        periods = {row["period"]: row for row in payload["usage"]}
        day_key, month_key = scheduler._cf_periods()
        assert periods["calls:" + day_key]["count"] == 3, payload
        assert periods["scans:" + month_key]["limit_value"] == 5000, payload
        assert any(m["key"] == "ratelimit" for m in payload["meta"]) or \
            any(m["key"] == "remaining" for m in payload["meta"]), payload
        db.close()
    print("[PASS] test_cloudflare_usage_headers")


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
    test_openintel_resolve_tlds_precedence()
    test_filter_keywords()
    test_openintel_csv_gz_read()
    test_search_cached_domains_with_cctld()
    test_virustotal_classify()
    test_abusech_classify()
    test_abusech_errors()
    test_abusech_feed_parse()
    test_abusech_feed_lookup()
    test_intel_signals()
    test_weekly_tracking_schedule()
    test_glob_matching()
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
    test_auto_whois_helpers()
    test_openintel_parquet_read()
    test_icann_auth_error_reporting()
    test_icann_failure_report()
    test_glob_search_cached_domains()
    test_cloudflare_radar_classify()
    test_cloudflare_radar_errors()
    test_cloudflare_dns_batch()
    test_cloudflare_usage_headers()
    print("\nAll tests passed.")
