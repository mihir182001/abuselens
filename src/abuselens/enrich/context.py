"""Domain context: RDAP (age, registrar), Team Cymru (IP -> ASN), crt.sh (TLS cert history).

All lookups are best-effort, rate-limited and bounded per run; failures yield NULLs rather
than exceptions so a flaky registry never breaks the pipeline.
"""
from __future__ import annotations

import datetime as dt
import socket
import time

import pandas as pd

from ..ingest import http


def rdap(domain: str) -> dict:
    out = {"domain_age_days": None, "registrar": None}
    try:
        data = http.get(f"https://rdap.org/domain/{domain}", retries=1, timeout=20).json()
    except Exception:
        return out
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                reg = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                out["domain_age_days"] = (dt.datetime.now(dt.timezone.utc) - reg).days
            except ValueError:
                pass
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            try:
                out["registrar"] = ent["vcardArray"][1][1][3]
            except (KeyError, IndexError, TypeError):
                pass
    return out


def asn_lookup(ip: str) -> dict:
    """Team Cymru IP-to-ASN over their whois service (port 43)."""
    out = {"asn": None, "asn_org": None}
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=10) as s:
            s.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
            resp = b""
            while chunk := s.recv(4096):
                resp += chunk
        lines = resp.decode(errors="ignore").strip().splitlines()
        if len(lines) >= 2:
            cols = [c.strip() for c in lines[1].split("|")]
            out["asn"] = int(cols[0]) if cols[0].isdigit() else None
            out["asn_org"] = cols[-1] if cols else None
    except Exception:
        pass
    return out


def cert_count(domain: str) -> int | None:
    try:
        return len(http.get("https://crt.sh/", params={"q": domain, "output": "json"},
                            retries=1, timeout=30).json())
    except Exception:
        return None


def enrich_domains(domains: list[str], max_n: int = 200, delay: float = 1.0) -> pd.DataFrame:
    rows = []
    for d in domains[:max_n]:
        row = {"domain": d, "enriched_at": dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)}
        row.update(rdap(d))
        try:
            ip = socket.gethostbyname(d)
            row.update(asn_lookup(ip))
        except OSError:
            row.update({"asn": None, "asn_org": None})
        row["cert_count"] = cert_count(d)
        rows.append(row)
        time.sleep(delay)
    cols = ["domain", "domain_age_days", "registrar", "asn", "asn_org", "cert_count", "enriched_at"]
    return pd.DataFrame(rows, columns=cols)
