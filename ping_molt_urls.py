#!/usr/bin/env python3
"""
ping_molt_urls.py

Extract URLs from a (potentially large) JSON file and probe them.
"Viable" defaults to: got an HTTP response AND status code not in {404, 410}.

Usage examples:
  python ping_molt_urls.py --input moltbook_ai_reports.json
  python ping_molt_urls.py --input moltbook_ai_reports.json --out viable_sites.txt
  python ping_molt_urls.py --input moltbook_ai_reports.json --csv results.csv
  python ping_molt_urls.py --input moltbook_ai_reports.json --regex-scan --max-urls 2000
  python ping_molt_urls.py --exclude-codes 404,410,500,502,503,504

Notes:
- Uses HEAD first; if blocked (405/403/etc), falls back to GET (streamed, minimal read).
- Skips private/local network URLs for safety (127.0.0.1, 10/8, 192.168/16, etc.)
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: pip install requests", file=sys.stderr)
    raise


URL_REGEX = re.compile(r"https?://[^\s\"\'<>()]+", re.IGNORECASE)


@dataclass(frozen=True)
class ProbeResult:
    url: str
    final_url: str
    status: Optional[int]          # None if network error
    ok: bool                       # viable by our criteria
    error: Optional[str] = None
    elapsed_ms: Optional[int] = None


def parse_exclude_codes(s: str) -> Set[int]:
    out: Set[int] = set()
    s = s.strip()
    if not s:
        return out
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        out.add(int(part))
    return out


def is_private_or_local_host(host: str) -> bool:
    """
    Return True if host is private/local IP (v4/v6) or obvious localhost.
    """
    if not host:
        return True
    h = host.strip().lower()
    if h in ("localhost",):
        return True
    # Strip brackets for IPv6 literal
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        # Not an IP literal (domain name). We'll allow it.
        return False


def normalize_url(u: str) -> Optional[str]:
    if not u:
        return None
    u = u.strip().strip('",\')]}')  # trim common trailing JSON/punct noise
    if not (u.startswith("http://") or u.startswith("https://")):
        return None
    try:
        p = urlparse(u)
    except Exception:
        return None
    if not p.scheme or not p.netloc:
        return None
    host = p.hostname or ""
    if is_private_or_local_host(host):
        return None
    # Normalize: lowercase scheme/host, keep path/query/fragment
    scheme = p.scheme.lower()
    netloc = p.netloc
    # netloc may include userinfo; keep as-is but lowercase hostname portion
    # Simple approach: rebuild with hostname lowercased when possible
    if p.hostname:
        lower_host = p.hostname.lower()
        if p.port:
            hostport = f"{lower_host}:{p.port}"
        else:
            hostport = lower_host
        # Preserve possible username/password
        if p.username or p.password:
            userinfo = p.username or ""
            if p.password:
                userinfo += f":{p.password}"
            netloc = f"{userinfo}@{hostport}"
        else:
            netloc = hostport
    rebuilt = urlunparse((scheme, netloc, p.path or "/", p.params, p.query, p.fragment))
    return rebuilt


def iter_urls_from_json_obj(obj: Any) -> Iterable[str]:
    """
    Walk an arbitrary JSON-like structure and yield values that look like URLs.
    - If a dict has key 'url', yield its value (if string).
    - Also scan any string values for embedded URLs via regex.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "url" and isinstance(v, str):
                yield v
            yield from iter_urls_from_json_obj(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_urls_from_json_obj(item)
    elif isinstance(obj, str):
        for m in URL_REGEX.findall(obj):
            yield m


def iter_urls_regex_scan_file(path: str) -> Iterable[str]:
    """
    Streaming-friendly scan: finds http(s) URLs in raw text without JSON parsing.
    Useful if the JSON is too big to load.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for m in URL_REGEX.findall(line):
                yield m


def load_urls(path: str, regex_scan: bool = False, max_urls: Optional[int] = None) -> List[str]:
    seen: Set[str] = set()
    urls: List[str] = []

    def add(u: str) -> None:
        nu = normalize_url(u)
        if not nu:
            return
        if nu not in seen:
            seen.add(nu)
            urls.append(nu)

    if regex_scan:
        for u in iter_urls_regex_scan_file(path):
            add(u)
            if max_urls and len(urls) >= max_urls:
                break
        return urls

    # JSON parse mode
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for u in iter_urls_from_json_obj(data):
        add(u)
        if max_urls and len(urls) >= max_urls:
            break
    return urls


def probe_one(url: str, timeout: float, user_agent: str, allow_redirects: bool = True) -> ProbeResult:
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    t0 = time.time()

    # Use a short-lived session per call; threads + shared session can be flaky
    try:
        # Try HEAD first
        r = requests.head(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        status = r.status_code
        final_url = str(r.url)

        # Some sites block HEAD or respond oddly; fall back to GET for certain cases
        if status in (405, 403, 400) or (status >= 500):
            r.close()
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects, stream=True)
            status = r.status_code
            final_url = str(r.url)
            # Read a tiny bit then close
            try:
                next(r.iter_content(chunk_size=64), b"")
            except StopIteration:
                pass
        r.close()

        elapsed_ms = int((time.time() - t0) * 1000)
        # ok-ness is decided outside (needs exclude list), but keep a preliminary “reachable”
        return ProbeResult(url=url, final_url=final_url, status=status, ok=True, error=None, elapsed_ms=elapsed_ms)

    except requests.RequestException as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        return ProbeResult(url=url, final_url=url, status=None, ok=False, error=str(e), elapsed_ms=elapsed_ms)


def classify(result: ProbeResult, exclude_codes: Set[int]) -> ProbeResult:
    """
    Decide viability based on status codes + reachability.
    Default behavior: viable if status is not None and not in exclude_codes.
    """
    if result.status is None:
        return ProbeResult(
            url=result.url, final_url=result.final_url, status=None, ok=False,
            error=result.error, elapsed_ms=result.elapsed_ms
        )
    if result.status in exclude_codes:
        return ProbeResult(
            url=result.url, final_url=result.final_url, status=result.status, ok=False,
            error=result.error, elapsed_ms=result.elapsed_ms
        )
    return ProbeResult(
        url=result.url, final_url=result.final_url, status=result.status, ok=True,
        error=result.error, elapsed_ms=result.elapsed_ms
    )


def write_txt(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def write_csv(path: str, rows: List[ProbeResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "final_url", "status", "ok", "elapsed_ms", "error"])
        for r in rows:
            w.writerow([r.url, r.final_url, r.status if r.status is not None else "", r.ok, r.elapsed_ms or "", r.error or ""])


def write_json(path: str, rows: List[ProbeResult]) -> None:
    payload = [
        {
            "url": r.url,
            "final_url": r.final_url,
            "status": r.status,
            "ok": r.ok,
            "elapsed_ms": r.elapsed_ms,
            "error": r.error,
        }
        for r in rows
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe URLs referenced in moltbook_ai_reports.json and list viable ones.")
    ap.add_argument("--input", default="moltbook_ai_reports.json", help="Path to JSON file (default: moltbook_ai_reports.json)")
    ap.add_argument("--regex-scan", action="store_true", help="Do a streaming regex scan instead of JSON parsing (better for huge files)")
    ap.add_argument("--max-urls", type=int, default=0, help="Limit number of URLs processed (0 = no limit)")
    ap.add_argument("--workers", type=int, default=24, help="Number of concurrent workers (default: 24)")
    ap.add_argument("--timeout", type=float, default=8.0, help="Timeout per request in seconds (default: 8)")
    ap.add_argument("--exclude-codes", default="404,410", help="Comma-separated HTTP status codes to treat as NOT viable (default: 404,410)")
    ap.add_argument("--ua", default="Mozilla/5.0 (compatible; URLProbe/1.0)", help="User-Agent string")
    ap.add_argument("--out", default="", help="Write viable URLs to this text file (one per line)")
    ap.add_argument("--csv", default="", help="Write full results to CSV")
    ap.add_argument("--json", default="", help="Write full results to JSON")
    ap.add_argument("--show-dead", action="store_true", help="Also print non-viable results to stdout")
    args = ap.parse_args()

    exclude_codes = parse_exclude_codes(args.exclude_codes)
    max_urls = args.max_urls if args.max_urls and args.max_urls > 0 else None

    urls = load_urls(args.input, regex_scan=args.regex_scan, max_urls=max_urls)
    if not urls:
        print("No URLs found (or all were filtered as local/private/non-http).", file=sys.stderr)
        return 2

    print(f"Found {len(urls)} unique URLs to probe.")

    results: List[ProbeResult] = []
    viable: List[str] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(probe_one, u, args.timeout, args.ua, True): u for u in urls}
        for fut in as_completed(futs):
            raw = fut.result()
            r = classify(raw, exclude_codes)
            results.append(r)
            if r.ok:
                # Print viable as we go
                code = r.status if r.status is not None else "ERR"
                line = f"{code}\t{r.final_url}"
                print(line)
                viable.append(r.final_url)
            elif args.show_dead:
                code = r.status if r.status is not None else "ERR"
                print(f"{code}\t{r.final_url}\t{r.error or ''}".rstrip())

    # Summary
    ok_count = sum(1 for r in results if r.ok)
    err_count = sum(1 for r in results if r.status is None)
    excluded_count = len(results) - ok_count - err_count

    print("\n==== Summary ====")
    print(f"Total probed: {len(results)}")
    print(f"Viable:       {ok_count}")
    print(f"Excluded:     {excluded_count} (status in {sorted(exclude_codes)})")
    print(f"Network errs: {err_count}")

    # Outputs
    if args.out:
        write_txt(args.out, viable)
        print(f"Wrote viable URLs to: {args.out}")
    if args.csv:
        write_csv(args.csv, sorted(results, key=lambda r: (not r.ok, r.status or 9999, r.url)))
        print(f"Wrote CSV results to: {args.csv}")
    if args.json:
        write_json(args.json, sorted(results, key=lambda r: (not r.ok, r.status or 9999, r.url)))
        print(f"Wrote JSON results to: {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
