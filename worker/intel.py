#!/usr/bin/env python3
"""Dormant-domain tracking signals (Intelligence).

Given the reputation results and the WHOIS state of a tracked domain, decide
whether it has shown an activation signal and describe it. Pure logic so it can
be unit-tested without network access.
"""

import json


def _ns_set(value):
    """Normalize a nameserver value (JSON string or list) into a lowercase set."""
    if not value:
        return set()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return set()
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {str(x).strip().lower() for x in value if str(x).strip()}


def compare_whois(baseline, whois_now):
    """Detect nameserver / registrar changes against the enrollment baseline.

    Returns ``(changed: bool, detail: str)``.
    """
    base = (baseline or {}).get("whois") or {}
    now = whois_now or {}
    details = []

    base_ns = _ns_set(base.get("name_servers"))
    now_ns = _ns_set(now.get("name_servers"))
    if base_ns and now_ns and base_ns != now_ns:
        details.append("nameservers changed")

    base_reg = str(base.get("registrar") or "").strip().lower()
    now_reg = str(now.get("registrar") or "").strip().lower()
    if base_reg and now_reg and base_reg != now_reg:
        details.append("registrar changed")

    return (len(details) > 0, "; ".join(details))


def evaluate(abusech_result, vt_result, whois_changed, whois_detail=""):
    """Combine the tracking signals into a result dict (activation on reputation)."""
    av = (abusech_result or {}).get("verdict")
    vv = (vt_result or {}).get("verdict")

    reasons = []
    if av in ("malicious", "suspicious"):
        reasons.append("abuse.ch: " + av)
    if vv in ("malicious", "suspicious", "dga"):
        reasons.append("VirusTotal: " + vv)

    signals = [{
        "type": "reputation",
        "abusech": av or "not_checked",
        "vt": vv or "not_checked",
    }]
    if whois_changed:
        signals.append({"type": "whois_change", "detail": whois_detail or "changed"})

    return {
        "activated": bool(reasons),
        "activated_reason": "; ".join(reasons),
        "signals": signals,
        "whois_changed": bool(whois_changed),
        "whois_detail": whois_detail,
    }
