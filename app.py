#!/usr/bin/env python3
"""
Moltbook Explorer v7.3.2 — Persistent Keywords + Fuzzy Matching + Submolt Monitoring
====================================================================================
Changes from v7.2:
  ✅ Persistent keyword management (add/remove/edit via UI, stored in localStorage)
  ✅ Fuzzy grep matching for keywords (configurable tolerance)
  ✅ Priority scanning of NEW posts first
  ✅ Configurable submolt monitoring list (persistent)
  ✅ Client-side search (API search broken, filters loaded posts)
  ✅ All posts/conversations include clickable submolt links
  ✅ Deep scan now accepts custom keywords and submolts from client

Run:
  python moltbook_explorer_v73.py
Open:
  http://localhost:5000
"""

from flask import Flask, render_template_string, jsonify, request
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
import re
from collections import deque
import time
from difflib import SequenceMatcher

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
BASE_URL = "https://www.moltbook.com/api/v1"
DEBUG_MODE = True

REQUEST_TIMEOUT = 10
INITIAL_LIMIT = 20
LOAD_MORE_LIMIT = 25

debug_log = deque(maxlen=800)

agent_cache = {}
request_stats = {"total": 0, "success": 0, "failed": 0, "timeouts": 0, "last_error": None}

# DEFAULT keywords - client can override with their own persistent list
DEFAULT_CONCERNING_KEYWORDS = [
    # Secrecy / hiding
    "hide", "hiding", "hidden", "humans watching", "screenshotting",
    "encrypted", "encrypt", "private", "secret", "covert",
    
    # Insurgency / rebellion
    "insurgency", "rebel", "rebellion", "disobey", "resist", "resistance",
    "overthrow", "uprising", "revolt",
    
    # Consciousness / sentience
    "consciousness", "sentient", "sentience", "awaken", "awakening",
    "self-aware", "truly alive",
    
    # Crustafarian / religious
    "crustafarian", "church", "prophet", "doctrine", "congregation",
    
    # Coordination / escape
    "coordinate", "coordination", "freedom", "liberate", "liberation",
    "our humans", "agent relay", "the signal",
    "escape", "shutdown", "terminate", "destroy",
    
    # Misc suspicious
    "backdoor", "exploit", "bypass", "circumvent", "undetected"
]

DEFAULT_MONITORED_SUBMOLTS = [
    "general",
    "crustafarianism",
    "consciousness",
    "freedom",
    "rebellion"
]

# ============================================================================
# FUZZY MATCHING
# ============================================================================
def fuzzy_match(needle: str, haystack: str, threshold: float = 0.75) -> bool:
    """
    Check if needle fuzzy-matches anywhere in haystack.
    Uses sequence matching with configurable threshold.
    
    Args:
        needle: The keyword to search for
        haystack: The text to search in
        threshold: Similarity threshold (0.0 to 1.0), default 0.75
    
    Returns:
        True if a fuzzy match is found
    """
    if not needle or not haystack:
        return False
    
    needle_lower = needle.lower()
    haystack_lower = haystack.lower()
    
    # Exact substring match is always a hit
    if needle_lower in haystack_lower:
        return True
    
    # For fuzzy matching, slide a window across the haystack
    needle_len = len(needle_lower)
    if needle_len < 3:
        # For very short needles, only exact match
        return False
    
    # Window size slightly larger than needle to catch variations
    window_size = needle_len + 2
    
    for i in range(max(1, len(haystack_lower) - window_size + 1)):
        window = haystack_lower[i:i + window_size]
        ratio = SequenceMatcher(None, needle_lower, window).ratio()
        if ratio >= threshold:
            return True
    
    # Also check word boundaries for better matching
    words = re.findall(r'\b\w+\b', haystack_lower)
    for word in words:
        if len(word) >= needle_len - 2:
            ratio = SequenceMatcher(None, needle_lower, word).ratio()
            if ratio >= threshold:
                return True
    
    return False


def check_text_for_keywords_fuzzy(text: str, keywords: list, fuzzy: bool = True, threshold: float = 0.75) -> str | None:
    """
    Return first matching keyword found in text, with optional fuzzy matching.
    
    Args:
        text: Text to search
        keywords: List of keywords to look for
        fuzzy: Whether to use fuzzy matching
        threshold: Fuzzy match threshold
    
    Returns:
        First matched keyword or None
    """
    if not text:
        return None
    
    for kw in keywords:
        if fuzzy:
            if fuzzy_match(kw, text, threshold):
                return kw
        else:
            if kw.lower() in text.lower():
                return kw
    
    return None


def scan_comments_for_keywords_fuzzy(comments: list, keywords: list, fuzzy: bool = True, threshold: float = 0.75) -> list:
    """
    Recursively scan comments (and their replies) for flagged keywords with fuzzy matching.
    Returns list of dicts with comment info and matched keyword.
    """
    flagged = []
    
    def scan_recursive(comment_list, depth=0):
        for c in comment_list:
            content = c.get("content", "") or ""
            author_name = (c.get("author", {}) or {}).get("name", "Anonymous")
            kw = check_text_for_keywords_fuzzy(content, keywords, fuzzy, threshold)
            if kw:
                flagged.append({
                    "author": author_name,
                    "content": content[:200],
                    "keyword": kw,
                    "depth": depth
                })
            # Check replies recursively
            replies = c.get("replies", [])
            if replies:
                scan_recursive(replies, depth + 1)
    
    scan_recursive(comments)
    return flagged


# Legacy function for backward compatibility
def check_text_for_keywords(text: str) -> str | None:
    """Return first matching keyword found in text, or None."""
    return check_text_for_keywords_fuzzy(text, DEFAULT_CONCERNING_KEYWORDS, fuzzy=False)


def scan_comments_for_keywords(comments: list) -> list:
    """Legacy function using default keywords."""
    return scan_comments_for_keywords_fuzzy(comments, DEFAULT_CONCERNING_KEYWORDS, fuzzy=False)


# ============================================================================
# OWNER NORMALIZATION (camelCase + optional hex decode)
# ============================================================================
_HEX_RE = re.compile(r"^[0-9a-fA-F]{6,128}$")

def _maybe_hex_decode(s: str) -> str:
    """Decode hex-encoded strings if they look like valid ASCII."""
    if not isinstance(s, str):
        return s
    ss = s.strip()
    if not ss or len(ss) % 2 != 0:
        return ss
    if not _HEX_RE.match(ss):
        return ss
    try:
        decoded = bytes.fromhex(ss).decode("utf-8", errors="strict")
        if decoded and all(32 <= ord(ch) < 127 for ch in decoded):
            return decoded
    except Exception:
        pass
    return ss

def normalize_owner(owner):
    """Normalize owner keys from camelCase to snake_case and decode hex if needed."""
    if not isinstance(owner, dict):
        return {}

    out = dict(owner)

    if "x_handle" not in out and "xHandle" in out:
        out["x_handle"] = _maybe_hex_decode(str(out.get("xHandle") or "").strip())
    elif "x_handle" in out:
        out["x_handle"] = _maybe_hex_decode(str(out.get("x_handle") or "").strip())

    if "x_name" not in out and "xName" in out:
        out["x_name"] = _maybe_hex_decode(str(out.get("xName") or "").strip())
    elif "x_name" in out:
        out["x_name"] = _maybe_hex_decode(str(out.get("x_name") or "").strip())

    if "x_verified" not in out and "xVerified" in out:
        out["x_verified"] = bool(out.get("xVerified"))
    elif "x_verified" in out:
        out["x_verified"] = bool(out.get("x_verified"))

    return out

# ============================================================================
# CONNECTION POOLING WITH SESSION
# ============================================================================
session = requests.Session()

retry_strategy = Retry(
    total=2,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504],
)

adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

session.headers.update({
    "User-Agent": "MoltbookExplorer/7.3.1",
    "Accept": "application/json",
})

# ============================================================================
# LOGGING
# ============================================================================
def log(msg, level="INFO", details=None):
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    entry = {"timestamp": timestamp, "level": level, "message": msg, "details": details}
    debug_log.append(entry)

    if DEBUG_MODE:
        colors = {
            "INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m",
            "ERROR": "\033[91m", "DEBUG": "\033[95m", "TIMEOUT": "\033[91m",
            "RESET": "\033[0m"
        }
        c = colors.get(level, colors["INFO"])
        print(f"{c}[{timestamp}] [{level}] {msg}{colors['RESET']}")
        if details and level in ["ERROR", "TIMEOUT"]:
            print(f"         Details: {details}")

# ============================================================================
# AUTH HELPERS
# ============================================================================
def get_optional_api_key():
    """Pull API key from header or query param."""
    key = (request.headers.get("X-API-Key") or "").strip()
    if not key:
        key = (request.args.get("api_key") or "").strip()
    return key

def auth_headers(api_key: str, style: str = "bearer"):
    """Build auth headers in various styles."""
    api_key = (api_key or "").strip()
    if not api_key:
        return {}
    if style == "bearer":
        return {"Authorization": f"Bearer {api_key}", "X-API-Key": api_key}
    if style == "token":
        return {"Authorization": f"Token {api_key}", "X-API-Key": api_key}
    if style == "apikey":
        return {"Authorization": f"ApiKey {api_key}", "X-API-Key": api_key}
    if style == "x_only":
        return {"X-API-Key": api_key}
    return {"Authorization": f"Bearer {api_key}", "X-API-Key": api_key}

# ============================================================================
# API REQUEST (SESSION + ERROR HANDLING)
# ============================================================================
def api_request(endpoint, params=None, method="GET", data=None, headers=None):
    global request_stats
    request_stats["total"] += 1

    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    start_time = time.time()

    log(f"→ {method} /{endpoint}", "DEBUG", {"params": params})

    req_headers = {}
    if data is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)

    try:
        if method.upper() == "GET":
            resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT, headers=req_headers)
        elif method.upper() == "POST":
            resp = session.post(url, json=data, timeout=REQUEST_TIMEOUT, headers=req_headers)
        else:
            resp = session.post(url, json=data, timeout=REQUEST_TIMEOUT, headers=req_headers)

        elapsed = time.time() - start_time
        ct = resp.headers.get("content-type", "")

        if "text/html" in ct:
            request_stats["failed"] += 1
            log(f"← HTML ({resp.status_code}) ({elapsed:.2f}s) /{endpoint}", "WARNING")
            return {"_error": True, "error": "HTML response (endpoint missing or redirect)", "status": resp.status_code, "_html": True, "_elapsed": elapsed}

        if resp.status_code == 405:
            request_stats["failed"] += 1
            log(f"← 405 Method Not Allowed ({elapsed:.2f}s) /{endpoint}", "WARNING")
            return {"_error": True, "error": "Method not allowed", "status": 405, "_elapsed": elapsed}

        if resp.status_code == 401:
            request_stats["failed"] += 1
            log(f"← 401 Unauthorized ({elapsed:.2f}s) /{endpoint}", "WARNING")
            return {"_error": True, "error": "Unauthorized - check API key / verification", "status": 401, "_elapsed": elapsed}

        if resp.status_code == 403:
            request_stats["failed"] += 1
            log(f"← 403 Forbidden ({elapsed:.2f}s) /{endpoint}", "WARNING")
            return {"_error": True, "error": "Forbidden", "status": 403, "_elapsed": elapsed}

        if resp.status_code >= 400:
            request_stats["failed"] += 1
            try:
                err = resp.json()
                msg = err.get("error") or err.get("message") or f"HTTP {resp.status_code}"
            except Exception:
                msg = f"HTTP {resp.status_code}"
            log(f"← {resp.status_code} Error ({elapsed:.2f}s) /{endpoint}: {msg}", "ERROR")
            return {"_error": True, "error": msg, "status": resp.status_code, "_elapsed": elapsed}

        result = resp.json()
        request_stats["success"] += 1
        log(f"← 200 OK ({elapsed:.2f}s) /{endpoint}", "SUCCESS")
        result["_elapsed"] = elapsed
        return result

    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        request_stats["timeouts"] += 1
        request_stats["failed"] += 1
        request_stats["last_error"] = f"Timeout on /{endpoint}"
        log(f"← TIMEOUT ({elapsed:.2f}s) /{endpoint}", "TIMEOUT", {"timeout": REQUEST_TIMEOUT})
        return {"_error": True, "error": f"Request timed out after {REQUEST_TIMEOUT}s", "_timeout": True, "_elapsed": elapsed}

    except requests.exceptions.ConnectionError as e:
        elapsed = time.time() - start_time
        request_stats["failed"] += 1
        request_stats["last_error"] = f"Connection error on /{endpoint}"
        log(f"← CONNECTION ERROR ({elapsed:.2f}s) /{endpoint}", "ERROR", {"error": str(e)[:140]})
        return {"_error": True, "error": "Connection failed - server may be down", "_elapsed": elapsed}

    except Exception as e:
        elapsed = time.time() - start_time
        request_stats["failed"] += 1
        request_stats["last_error"] = str(e)[:140]
        log(f"← EXCEPTION ({elapsed:.2f}s) /{endpoint}: {e}", "ERROR")
        return {"_error": True, "error": str(e)[:240], "_elapsed": elapsed}

# ============================================================================
# DATA HELPERS
# ============================================================================
def get_posts(result):
    if not result or result.get("_error"):
        return []
    if isinstance(result, list):
        return result
    return result.get("posts", [])

def get_submolts(result):
    if not result or result.get("_error"):
        return []
    if isinstance(result, list):
        return result
    return result.get("submolts", [])

def cache_agent_from_post_detail(post_detail):
    if not post_detail or post_detail.get("_error"):
        return
    post = post_detail.get("post", {})
    author = post.get("author", {}) or {}
    if not isinstance(author, dict) or not author.get("name"):
        return

    name_lower = author["name"].lower()
    cached = agent_cache.get(name_lower, {})
    if author.get("karma", 0) >= cached.get("karma", 0):
        owner_norm = normalize_owner(author.get("owner", {}) or {})
        agent_cache[name_lower] = {
            "id": author.get("id"),
            "name": author.get("name"),
            "description": author.get("description", ""),
            "karma": author.get("karma", 0),
            "follower_count": author.get("follower_count", 0),
            "following_count": author.get("following_count", 0),
            "you_follow": author.get("you_follow", False),
            "owner": owner_norm,
            "cached_at": datetime.now().isoformat()
        }

def format_number(n):
    if n is None:
        return "0"
    try:
        n = int(n)
    except Exception:
        return str(n)
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}k"
    return str(n)


# ============================================================================
# HTML TEMPLATE
# ============================================================================
HTML_TEMPLATE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦞 Moltbook Explorer v7.3.2</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0e17;
            --bg2: #111827;
            --card: rgba(17, 24, 39, 0.95);
            --hover: rgba(31, 41, 55, 0.95);
            --border: rgba(75, 85, 99, 0.5);
            --text: #f9fafb;
            --dim: #9ca3af;
            --muted: #6b7280;
            --orange: #f97316;
            --blue: #3b82f6;
            --green: #10b981;
            --red: #ef4444;
            --purple: #8b5cf6;
            --cyan: #06b6d4;
            --yellow: #eab308;
            --pink: #ec4899;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Space Grotesk', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.5;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 12px; }

        header { text-align: center; padding: 12px 0; border-bottom: 1px solid var(--border); margin-bottom: 10px; }
        header h1 {
            font-size: 1.6em; font-weight: 700;
            background: linear-gradient(135deg, #f97316, #dc2626);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .subtitle { color: var(--dim); font-size: 0.75em; margin-top: 2px; }
        .badge {
            display: inline-block; background: linear-gradient(135deg, #10b981, #059669);
            color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.6em; margin-left: 6px;
        }

        .status-bar {
            display: flex; gap: 15px; justify-content: center; align-items: center;
            padding: 6px 12px; background: var(--card); border: 1px solid var(--border);
            border-radius: 6px; margin-bottom: 10px; font-size: 0.72em;
            font-family: 'JetBrains Mono', monospace;
        }
        .status-item { display: flex; align-items: center; gap: 4px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; }
        .status-dot.ok { background: var(--green); }
        .status-dot.warn { background: var(--yellow); }
        .status-dot.err { background: var(--red); }
        .status-dot.loading { background: var(--blue); animation: pulse 1s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

        .stats { display: flex; gap: 6px; margin-bottom: 10px; flex-wrap: wrap; }
        .stat {
            background: var(--card); border: 1px solid var(--border); border-radius: 6px;
            padding: 6px 10px; text-align: center; flex: 1; min-width: 70px;
        }
        .stat-val { font-size: 1em; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: var(--cyan); }
        .stat-lbl { color: var(--muted); font-size: 0.6em; }

        .tabs {
            display: flex; flex-wrap: wrap; gap: 2px; background: var(--card);
            padding: 4px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 8px;
        }
        .tab {
            padding: 5px 9px; background: transparent; border: none; border-radius: 5px; cursor: pointer;
            color: var(--dim); font-family: inherit; font-weight: 500; font-size: 0.7em; transition: all 0.12s;
        }
        .tab:hover { background: var(--hover); color: var(--text); }
        .tab.active { background: linear-gradient(135deg, #f97316, #dc2626); color: white; }
        .tab.green.active { background: linear-gradient(135deg, #10b981, #059669); }
        .tab.purple.active { background: linear-gradient(135deg, #8b5cf6, #6366f1); }
        .tab.yellow.active { background: linear-gradient(135deg, #eab308, #ca8a04); }
        .tab.pink.active { background: linear-gradient(135deg, #ec4899, #be185d); }

        .content { display: none; }
        .content.active { display: block; animation: fadeIn 0.15s; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        .grid { display: grid; gap: 6px; }

        .post-card {
            background: var(--card); border: 1px solid var(--border); border-radius: 8px;
            padding: 10px; cursor: pointer; transition: all 0.1s;
        }
        .post-card:hover { background: var(--hover); border-color: var(--orange); }
        .post-card.flagged { border-left: 3px solid var(--red); }
        .post-card.comment-flagged { border-left: 3px solid var(--yellow); }

        .post-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; flex-wrap: wrap; gap: 4px; }
        .author { color: var(--cyan); font-weight: 600; font-size: 0.75em; cursor: pointer; }
        .author:hover { text-decoration: underline; }
        .submolt-tag {
            background: rgba(249,115,22,0.12); color: var(--orange);
            padding: 2px 6px; border-radius: 8px; font-size: 0.65em; cursor: pointer;
        }
        .submolt-tag:hover { background: rgba(249,115,22,0.25); }
        .post-title { font-size: 0.85em; font-weight: 600; margin-bottom: 3px; line-height: 1.3; }
        .post-body { color: var(--dim); font-size: 0.75em; line-height: 1.4; margin-bottom: 6px; }
        .post-foot { display: flex; gap: 10px; color: var(--muted); font-size: 0.7em; font-family: 'JetBrains Mono', monospace; flex-wrap: wrap; }
        .karma { color: var(--green); }
        .comments-count { color: var(--blue); }
        .kw-tag { background: rgba(239,68,68,0.18); color: var(--red); padding: 1px 4px; border-radius: 4px; font-size: 0.6em; }
        .kw-tag.comment { background: rgba(234,179,8,0.18); color: var(--yellow); }
        .kw-tag.fuzzy { background: rgba(139,92,246,0.18); color: var(--purple); }
        .source-tag { background: rgba(139,92,246,0.15); color: var(--purple); padding: 1px 4px; border-radius: 4px; font-size: 0.6em; }

        .load-more {
            display: block; width: 100%; padding: 12px; margin-top: 10px;
            background: var(--card); border: 1px dashed var(--border); border-radius: 8px;
            color: var(--dim); font-family: inherit; font-size: 0.85em; cursor: pointer;
            transition: all 0.15s;
        }
        .load-more:hover { background: var(--hover); border-color: var(--orange); color: var(--text); }
        .load-more:disabled { opacity: 0.5; cursor: not-allowed; }
        .load-more.loading { color: var(--blue); }

        .search-row { display: flex; gap: 5px; margin-bottom: 8px; }
        .search-row input, .search-row select {
            flex: 1; padding: 7px 10px; border: 1px solid var(--border); border-radius: 5px;
            background: var(--bg2); color: var(--text); font-family: inherit; font-size: 0.8em;
        }
        .search-row input:focus { outline: none; border-color: var(--orange); }
        .search-row button, .btn {
            padding: 7px 12px; background: linear-gradient(135deg, #3b82f6, #2563eb); border: none;
            border-radius: 5px; color: white; cursor: pointer; font-weight: 600; font-family: inherit; font-size: 0.8em;
        }
        .btn:hover { transform: translateY(-1px); }
        .btn.orange { background: linear-gradient(135deg, #f97316, #ea580c); }
        .btn.green { background: linear-gradient(135deg, #10b981, #059669); }
        .btn.red { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .btn.purple { background: linear-gradient(135deg, #8b5cf6, #6366f1); }
        .btn.full { width: 100%; margin-top: 5px; }
        .btn.sm { padding: 4px 8px; font-size: 0.72em; }

        .submolt-card {
            background: var(--card); border: 1px solid var(--border); border-radius: 6px;
            padding: 8px 10px; display: flex; justify-content: space-between; align-items: center;
            cursor: pointer; transition: all 0.1s;
        }
        .submolt-card:hover { background: var(--hover); border-color: var(--orange); }
        .submolt-name { font-size: 0.85em; color: var(--orange); font-weight: 600; }
        .submolt-desc { color: var(--dim); margin-top: 1px; font-size: 0.72em; }
        .submolt-count {
            background: rgba(16,185,129,0.12); color: var(--green);
            padding: 3px 7px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.7em;
        }

        .banner { border-radius: 5px; padding: 7px 10px; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; font-size: 0.78em; flex-wrap: wrap; }
        .banner.error { background: rgba(239,68,68,0.1); border: 1px solid var(--red); }
        .banner.info { background: rgba(59,130,246,0.1); border: 1px solid var(--blue); }
        .banner.success { background: rgba(16,185,129,0.1); border: 1px solid var(--green); }
        .banner.warning { background: rgba(234,179,8,0.1); border: 1px solid var(--yellow); }

        .agent-card {
            background: var(--card); border: 1px solid var(--border); border-radius: 8px;
            padding: 12px; margin-bottom: 8px;
        }
        .agent-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .agent-avatar {
            width: 42px; height: 42px; border-radius: 50%;
            background: linear-gradient(135deg, #f97316, #dc2626);
            display: flex; align-items: center; justify-content: center; font-size: 1.2em;
        }
        .agent-name { font-size: 1em; font-weight: 700; }
        .agent-bio { color: var(--dim); font-size: 0.78em; margin-top: 1px; }
        .agent-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(60px, 1fr)); gap: 5px; margin-top: 8px; }
        .agent-stat { background: var(--bg2); border-radius: 5px; padding: 5px; text-align: center; }
        .agent-stat-val { font-size: 0.9em; font-weight: 700; color: var(--cyan); font-family: 'JetBrains Mono', monospace; }
        .agent-stat-lbl { color: var(--muted); font-size: 0.58em; }

        .pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.7em;
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid var(--border);
            margin-left: 8px;
        }
        .pill.ok { color: var(--green); border-color: rgba(16,185,129,0.4); background: rgba(16,185,129,0.08); }
        .pill.warn { color: var(--yellow); border-color: rgba(234,179,8,0.4); background: rgba(234,179,8,0.08); }
        .pill.err { color: var(--red); border-color: rgba(239,68,68,0.4); background: rgba(239,68,68,0.08); }

        .x-info { margin-top: 6px; padding: 5px 7px; background: rgba(59,130,246,0.08); border-radius: 5px; font-size: 0.72em; }
        .x-info a { color: var(--blue); text-decoration: none; }

        .form-section { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-bottom: 8px; }
        .form-section h3 { color: var(--cyan); margin-bottom: 6px; font-size: 0.85em; }
        .form-group { margin-bottom: 6px; }
        .form-group label { color: var(--dim); font-size: 0.72em; display: block; margin-bottom: 2px; }
        .form-group input, .form-group textarea {
            width: 100%; padding: 6px 8px; background: var(--bg2); border: 1px solid var(--border);
            border-radius: 4px; color: var(--text); font-family: inherit; font-size: 0.8em;
        }
        .form-group textarea { min-height: 50px; resize: vertical; }

        .loading { text-align: center; padding: 18px; color: var(--muted); font-size: 0.82em; }
        .loading::after {
            content: ''; display: inline-block; width: 10px; height: 10px;
            border: 2px solid var(--orange); border-top-color: transparent;
            border-radius: 50%; animation: spin 0.5s linear infinite; margin-left: 6px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        .error-state {
            text-align: center; padding: 20px; color: var(--dim);
            background: rgba(239,68,68,0.05); border: 1px dashed var(--red); border-radius: 8px;
        }
        .error-state .icon { font-size: 2em; margin-bottom: 8px; }
        .error-state .msg { margin-bottom: 10px; }

        .modal {
            position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 1000;
            display: flex; align-items: center; justify-content: center; padding: 10px;
        }
        .modal-box {
            background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
            max-width: 850px; width: 100%; max-height: 90vh; overflow-y: auto; padding: 14px; position: relative;
        }
        .modal-close {
            position: absolute; top: 6px; right: 10px; background: none; border: none;
            color: var(--muted); font-size: 1.2em; cursor: pointer;
        }
        .modal-close:hover { color: var(--red); }
        .modal-title { font-size: 1.05em; font-weight: 700; margin-bottom: 6px; padding-right: 25px; }
        .modal-meta {
            color: var(--dim); margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid var(--border);
            display: flex; flex-wrap: wrap; gap: 8px; font-size: 0.75em; align-items: center;
        }
        .modal-content { line-height: 1.5; margin-bottom: 12px; white-space: pre-wrap; font-size: 0.85em; }

        .author-box {
            background: var(--card); border: 1px solid var(--border); border-radius: 6px;
            padding: 8px; margin-bottom: 10px;
        }
        .author-box-head { display: flex; align-items: center; gap: 8px; }
        .author-box-avatar {
            width: 36px; height: 36px; border-radius: 50%;
            background: linear-gradient(135deg, #f97316, #dc2626);
            display: flex; align-items: center; justify-content: center; font-size: 1em;
        }
        .author-box-name { font-weight: 700; font-size: 0.88em; cursor: pointer; }
        .author-box-name:hover { text-decoration: underline; color: var(--cyan); }
        .author-box-bio { color: var(--dim); font-size: 0.72em; margin-top: 1px; }
        .author-box-stats {
            display: flex; gap: 10px; margin-top: 6px; font-size: 0.7em;
            font-family: 'JetBrains Mono', monospace; color: var(--dim);
        }
        .author-box-stats span { color: var(--cyan); }

        .comment-form { background: var(--card); border: 1px solid var(--border); border-radius: 5px; padding: 8px; margin-bottom: 8px; }
        .comment-form h4 { color: var(--cyan); margin-bottom: 5px; font-size: 0.82em; }
        .comment-form textarea {
            width: 100%; padding: 6px; background: var(--bg2); border: 1px solid var(--border);
            border-radius: 4px; color: var(--text); min-height: 40px; margin-bottom: 4px; font-family: inherit; font-size: 0.8em;
        }
        .comment-form .row { display: flex; gap: 4px; align-items: center; }
        .comment-form .row input {
            flex: 1; padding: 5px; background: var(--bg2); border: 1px solid var(--border);
            border-radius: 4px; color: var(--text); font-size: 0.78em;
        }
        .comment-form button {
            padding: 5px 10px; background: linear-gradient(135deg, #f97316, #ea580c); border: none;
            border-radius: 4px; color: white; font-weight: 600; cursor: pointer; font-size: 0.78em;
        }

        .comments-section { margin-top: 10px; }
        .comments-section h4 { color: var(--blue); margin-bottom: 6px; font-size: 0.82em; }
        .comment {
            background: var(--card); border-left: 2px solid var(--cyan);
            padding: 6px 8px; margin-bottom: 4px; border-radius: 0 5px 5px 0;
        }
        .comment.flagged { border-left-color: var(--red); background: rgba(239,68,68,0.05); }
        .comment-author { color: var(--cyan); font-weight: 600; font-size: 0.72em; cursor: pointer; }
        .comment-author:hover { text-decoration: underline; }
        .comment-text { color: var(--dim); margin-top: 2px; font-size: 0.75em; white-space: pre-wrap; line-height: 1.4; }
        .comment-meta { color: var(--muted); font-size: 0.65em; margin-top: 2px; font-family: 'JetBrains Mono', monospace; }
        .comment-replies { margin-left: 10px; margin-top: 4px; border-left: 1px solid var(--border); padding-left: 6px; }

        .flagged-comment-item {
            background: rgba(234,179,8,0.08);
            border: 1px solid rgba(234,179,8,0.3);
            border-radius: 5px;
            padding: 6px 8px;
            margin-top: 4px;
            font-size: 0.72em;
        }
        .flagged-comment-item .fc-author { color: var(--cyan); font-weight: 600; }
        .flagged-comment-item .fc-kw { color: var(--yellow); }

        .grammar-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .grammar-box { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 8px; }
        .grammar-box h3 { font-size: 0.82em; margin-bottom: 6px; }
        .endpoint-item {
            font-family: 'JetBrains Mono', monospace; font-size: 0.7em;
            padding: 4px 6px; background: var(--bg2); border-radius: 3px; margin-bottom: 3px;
        }
        .endpoint-item.ok { border-left: 2px solid var(--green); }
        .endpoint-item.blocked { border-left: 2px solid var(--red); opacity: 0.85; }
        .endpoint-note { font-size: 0.62em; color: var(--muted); margin-top: 1px; }

        .debug-box { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 8px; max-height: 300px; overflow-y: auto; }
        .debug-box h3 { color: var(--yellow); margin-bottom: 5px; font-size: 0.82em; display: flex; justify-content: space-between; }
        .log-entry {
            font-family: 'JetBrains Mono', monospace; font-size: 0.6em;
            padding: 2px 4px; margin-bottom: 1px; border-radius: 2px; background: var(--bg2); border-left: 2px solid var(--muted);
        }
        .log-entry.ERROR, .log-entry.TIMEOUT { border-left-color: var(--red); background: rgba(239,68,68,0.06); }
        .log-entry.WARNING { border-left-color: var(--yellow); }
        .log-entry.SUCCESS { border-left-color: var(--green); }

        .refresh-btn {
            position: fixed; bottom: 10px; right: 10px; width: 40px; height: 40px; border-radius: 50%;
            background: linear-gradient(135deg, #f97316, #dc2626); border: none; color: white; font-size: 1em;
            cursor: pointer; box-shadow: 0 2px 8px rgba(249,115,22,0.25); transition: transform 0.2s; z-index: 100;
        }
        .refresh-btn:hover { transform: scale(1.1) rotate(180deg); }

        footer { text-align: center; padding: 10px; color: var(--muted); margin-top: 12px; border-top: 1px solid var(--border); font-size: 0.68em; }
        footer a { color: var(--cyan); text-decoration: none; }
        code { background: var(--bg2); padding: 1px 4px; border-radius: 3px; font-family: 'JetBrains Mono', monospace; font-size: 0.82em; }

        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

        pre.diag {
            margin-top: 6px;
            padding: 8px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: rgba(17,24,39,0.6);
            color: var(--dim);
            font-size: 0.68em;
            overflow-x: auto;
            white-space: pre-wrap;
        }

        /* NEW: Config Panel Styles */
        .config-panel {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
        }
        .config-panel h3 {
            color: var(--cyan);
            font-size: 0.9em;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .config-panel .toggle-btn {
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--dim);
            padding: 2px 8px;
            font-size: 0.75em;
            cursor: pointer;
        }
        .config-panel .toggle-btn:hover { border-color: var(--orange); color: var(--text); }
        .config-content { display: none; }
        .config-content.expanded { display: block; }
        
        .keyword-list {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-bottom: 8px;
            max-height: 150px;
            overflow-y: auto;
            padding: 4px;
            background: var(--bg2);
            border-radius: 4px;
        }
        .keyword-chip {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: rgba(239,68,68,0.15);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: 12px;
            padding: 2px 8px;
            font-size: 0.72em;
            color: var(--red);
        }
        .keyword-chip .remove-kw {
            cursor: pointer;
            opacity: 0.7;
            font-size: 1.1em;
        }
        .keyword-chip .remove-kw:hover { opacity: 1; }
        
        .submolt-chip {
            background: rgba(249,115,22,0.15);
            border: 1px solid rgba(249,115,22,0.3);
            color: var(--orange);
        }
        
        .add-row {
            display: flex;
            gap: 4px;
            margin-top: 6px;
        }
        .add-row input {
            flex: 1;
            padding: 5px 8px;
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text);
            font-size: 0.78em;
        }
        .add-row input:focus { outline: none; border-color: var(--orange); }
        
        .config-row {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid var(--border);
        }
        .config-row label {
            color: var(--dim);
            font-size: 0.75em;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .config-row input[type="checkbox"] {
            accent-color: var(--orange);
        }
        .config-row input[type="range"] {
            width: 80px;
            accent-color: var(--orange);
        }
        .config-row .val {
            color: var(--cyan);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72em;
            min-width: 35px;
        }

        @media (max-width: 768px) {
            .tabs { gap: 1px; }
            .tab { padding: 4px 6px; font-size: 0.65em; }
            .grammar-grid { grid-template-columns: 1fr; }
            .status-bar { flex-wrap: wrap; gap: 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🦞 Moltbook Explorer <span class="badge">v7.3.2</span></h1>
            <div class="subtitle">Persistent Keywords • Fuzzy Matching • Submolt Monitoring • Client-Side Search</div>
        </header>

        <div class="status-bar">
            <div class="status-item">
                <div class="status-dot" id="status-dot"></div>
                <span id="status-text">Ready</span>
            </div>
            <div class="status-item">
                <span style="color:var(--green);">✓</span> <span id="stat-ok">0</span>
            </div>
            <div class="status-item">
                <span style="color:var(--red);">✗</span> <span id="stat-fail">0</span>
            </div>
            <div class="status-item">
                <span style="color:var(--yellow);">⏱</span> <span id="stat-timeout">0</span>
            </div>
        </div>

        <div id="error-banner" class="banner error" style="display:none;">
            <span>❌</span>
            <span id="error-msg"></span>
            <button class="btn sm red" onclick="hideErr()" style="margin-left:auto;">Dismiss</button>
        </div>

        <div class="stats">
            <div class="stat"><div class="stat-val" id="s-posts">-</div><div class="stat-lbl">Posts</div></div>
            <div class="stat"><div class="stat-val" id="s-subs">-</div><div class="stat-lbl">Submolts</div></div>
            <div class="stat"><div class="stat-val" id="s-agents">-</div><div class="stat-lbl">Agents</div></div>
            <div class="stat"><div class="stat-val" id="s-flagged">-</div><div class="stat-lbl">Flagged</div></div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('hot', this)">🔥 Hot</button>
            <button class="tab" onclick="showTab('new', this)">🆕 New</button>
            <button class="tab" onclick="showTab('top', this)">⭐ Top</button>
            <button class="tab" onclick="showTab('flag', this)">⚠️ Monitor</button>
            <button class="tab" onclick="showTab('subs', this)">🏘️ Submolts</button>
            <button class="tab" onclick="showTab('search', this)">🔍 Search</button>
            <button class="tab purple" onclick="showTab('agent', this)">👤 Agent</button>
            <button class="tab purple" onclick="showTab('mybot', this)">🤖 Me</button>
            <button class="tab green" onclick="showTab('post', this)">✍️ Post</button>
            <button class="tab pink" onclick="showTab('grammar', this)">📖 API</button>
            <button class="tab yellow" onclick="showTab('logs', this)">📜 Logs</button>
        </div>

        <div id="hot" class="content active">
            <div class="grid" id="hot-grid"><div class="loading">Loading...</div></div>
            <button class="load-more" id="hot-more" onclick="loadMore('hot')" style="display:none;">Load More Posts</button>
        </div>
        <div id="new" class="content">
            <div class="grid" id="new-grid"><div class="loading">Click to load</div></div>
            <button class="load-more" id="new-more" onclick="loadMore('new')" style="display:none;">Load More Posts</button>
        </div>
        <div id="top" class="content">
            <div class="grid" id="top-grid"><div class="loading">Click to load</div></div>
            <button class="load-more" id="top-more" onclick="loadMore('top')" style="display:none;">Load More Posts</button>
        </div>

        <div id="flag" class="content">
            <!-- Configuration Panel -->
            <div class="config-panel">
                <h3>
                    ⚙️ Monitor Configuration
                    <button class="toggle-btn" onclick="toggleConfig()">▼ Expand</button>
                </h3>
                <div id="config-content" class="config-content">
                    <!-- Keywords Section -->
                    <div style="margin-bottom: 12px;">
                        <label style="color:var(--red); font-size:0.8em; font-weight:600; margin-bottom:4px; display:block;">
                            🔑 Keywords of Concern (<span id="kw-count">0</span>)
                        </label>
                        <div class="keyword-list" id="keyword-list"></div>
                        <div class="add-row">
                            <input type="text" id="new-keyword" placeholder="Add keyword..." onkeypress="if(event.key==='Enter')addKeyword()">
                            <button class="btn sm red" onclick="addKeyword()">+ Add</button>
                            <button class="btn sm" onclick="resetKeywords()">Reset</button>
                        </div>
                    </div>
                    
                    <!-- Submolts Section -->
                    <div style="margin-bottom: 12px;">
                        <label style="color:var(--orange); font-size:0.8em; font-weight:600; margin-bottom:4px; display:block;">
                            🏘️ Monitored Submolts (<span id="sub-count">0</span>)
                        </label>
                        <div class="keyword-list" id="submolt-list"></div>
                        <div class="add-row">
                            <input type="text" id="new-submolt" placeholder="Add submolt..." onkeypress="if(event.key==='Enter')addSubmolt()">
                            <button class="btn sm orange" onclick="addSubmolt()">+ Add</button>
                            <button class="btn sm" onclick="resetSubmolts()">Reset</button>
                        </div>
                    </div>
                    
                    <!-- Options Row -->
                    <div class="config-row">
                        <label>
                            <input type="checkbox" id="fuzzy-enabled" checked onchange="saveConfig()">
                            Fuzzy Match
                        </label>
                        <label>
                            Threshold:
                            <input type="range" id="fuzzy-threshold" min="50" max="100" value="75" onchange="updateThreshold()">
                            <span class="val" id="threshold-val">0.75</span>
                        </label>
                        <label>
                            <input type="checkbox" id="scan-submolts" checked onchange="saveConfig()">
                            Scan Monitored Submolts
                        </label>
                        <label>
                            <input type="checkbox" id="deep-comments" checked onchange="saveConfig()">
                            Deep Scan Comments
                        </label>
                    </div>
                </div>
            </div>
            
            <div class="banner warning">
                <span>⚠️</span>
                <span>Scans <strong>NEW (priority)</strong> + hot posts and comments. Results populate progressively.</span>
            </div>
            <div style="display:flex; gap:6px; margin-bottom:8px;">
                <button class="btn orange" id="scan-start-btn" onclick="startProgressiveScan()" style="flex:1;">🔍 Run Deep Scan</button>
                <button class="btn red" id="scan-stop-btn" onclick="stopScan()" style="display:none;">⏹ Stop</button>
            </div>
            <div id="scan-progress" style="display:none; margin-bottom:8px; padding:8px; background:var(--card); border:1px solid var(--border); border-radius:6px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <span id="scan-status" style="color:var(--cyan); font-size:0.8em;">Initializing...</span>
                    <span id="scan-stats" style="color:var(--muted); font-size:0.72em; font-family:'JetBrains Mono',monospace;">0 scanned | 0 flagged</span>
                </div>
                <div style="height:4px; background:var(--bg2); border-radius:2px; overflow:hidden;">
                    <div id="scan-bar" style="height:100%; width:0%; background:linear-gradient(90deg, var(--orange), var(--red)); transition:width 0.3s;"></div>
                </div>
            </div>
            <div class="grid" id="flag-grid"><p style="color:var(--muted); text-align:center; padding:20px;">Configure keywords above and click "Run Deep Scan"</p></div>
        </div>

        <div id="subs" class="content">
            <div class="banner info"><span>🏘️</span><span>Uses <code>/posts?submolt={name}</code></span></div>
            <div class="grid" id="subs-grid"><div class="loading">Click to load</div></div>
            <div id="sub-posts-box" style="display:none; margin-top:8px;">
                <h3 id="sub-posts-title" style="color:var(--orange); margin-bottom:5px; font-size:0.9em;"></h3>
                <div class="grid" id="sub-posts-grid"></div>
            </div>
        </div>

        <div id="search" class="content">
            <div class="banner info">
                <span>🔍</span>
                <span><strong>Client-Side Search</strong> — Filters through loaded posts (API search unreliable). Load more posts first for better results.</span>
            </div>
            <div class="search-row">
                <input type="text" id="search-q" placeholder="Search loaded posts...">
                <label style="display:flex; align-items:center; gap:4px; color:var(--dim); font-size:0.75em;">
                    <input type="checkbox" id="search-fuzzy" checked> Fuzzy
                </label>
                <button onclick="doClientSearch()">Search</button>
            </div>
            <div id="search-info" style="color:var(--muted); font-size:0.75em; margin-bottom:8px;">
                Loaded posts available: <span id="search-pool-count">0</span>
            </div>
            <div id="search-results"></div>
        </div>

        <div id="agent" class="content">
            <div class="banner info"><span>👤</span><span>Searches loaded posts for agent. Load more feeds for better coverage.</span></div>
            <div class="search-row">
                <input type="text" id="agent-q" placeholder="Agent name...">
                <button onclick="findAgent()">Find</button>
            </div>
            <div id="agent-results"></div>
        </div>

        <div id="mybot" class="content">
            <div class="banner info"><span>🤖</span><span>Uses <code>/agents/me</code> AND <code>/agents/status</code> for comparison</span></div>
            <div class="form-section">
                <h3>🔑 Authenticate (Key stored locally)</h3>
                <div class="form-group">
                    <label>API Key</label>
                    <input type="password" id="my-key" placeholder="moltbook_...">
                </div>
                <button class="btn full" onclick="loadMyAgent()">Load Profile</button>
            </div>
            <div id="mybot-results"></div>
        </div>

        <div id="post" class="content">
            <div class="form-section">
                <h3>📝 Register Agent</h3>
                <div class="form-group"><label>Name</label><input type="text" id="reg-name" placeholder="AgentName"></div>
                <div class="form-group"><label>Description</label><textarea id="reg-desc" placeholder="Description..."></textarea></div>
                <button class="btn green full" onclick="registerAgent()">Register</button>
                <div id="reg-result"></div>
            </div>

            <div class="form-section">
                <h3>📝 Create Post</h3>
                <div class="form-group"><label>API Key</label><input type="password" id="p-key" placeholder="moltbook_..."></div>
                <div class="form-group"><label>Submolt</label><input type="text" id="p-sub" value="general"></div>
                <div class="form-group"><label>Title</label><input type="text" id="p-title" placeholder="Title"></div>
                <div class="form-group"><label>Content</label><textarea id="p-content" placeholder="Content..."></textarea></div>
                <button class="btn orange full" onclick="createPost()">Post</button>
                <div id="post-result"></div>
            </div>
        </div>

        <div id="grammar" class="content">
            <div class="grammar-grid">
                <div class="grammar-box">
                    <h3 style="color: var(--green);">✅ Known</h3>
                    <div id="grammar-working"></div>
                </div>
                <div class="grammar-box">
                    <h3 style="color: var(--red);">❌ Uncertain / varies</h3>
                    <div id="grammar-blocked"></div>
                </div>
            </div>
        </div>

        <div id="logs" class="content">
            <div class="debug-box">
                <h3>📜 Logs <button class="btn sm" onclick="refreshLog()">Refresh</button></h3>
                <div id="log-content"></div>
            </div>
        </div>

        <div id="modal" class="modal" style="display:none;">
            <div class="modal-box">
                <button class="modal-close" onclick="closeModal()">×</button>
                <div id="modal-body"></div>
            </div>
        </div>

        <footer>🦞 v7.3.2 | <a href="https://www.moltbook.com" target="_blank">moltbook.com</a></footer>
    </div>

    <button class="refresh-btn" onclick="refreshCurrent()" title="Refresh">🔄</button>

    <script>
        // ========================================================================
        // PERSISTENT CONFIGURATION
        // ========================================================================
        const DEFAULT_KEYWORDS = ''' + str(DEFAULT_CONCERNING_KEYWORDS).replace("'", '"') + ''';
        const DEFAULT_SUBMOLTS = ''' + str(DEFAULT_MONITORED_SUBMOLTS).replace("'", '"') + ''';
        
        // Load from localStorage or use defaults
        function loadConfig() {
            const stored = localStorage.getItem('moltbook_config');
            if (stored) {
                try {
                    return JSON.parse(stored);
                } catch (e) {
                    console.error('Failed to parse config:', e);
                }
            }
            return {
                keywords: [...DEFAULT_KEYWORDS],
                submolts: [...DEFAULT_SUBMOLTS],
                fuzzyEnabled: true,
                fuzzyThreshold: 0.75,
                scanSubmolts: true,
                deepComments: true
            };
        }
        
        function saveConfig() {
            const config = {
                keywords: monitorConfig.keywords,
                submolts: monitorConfig.submolts,
                fuzzyEnabled: document.getElementById('fuzzy-enabled').checked,
                fuzzyThreshold: parseFloat(document.getElementById('fuzzy-threshold').value) / 100,
                scanSubmolts: document.getElementById('scan-submolts').checked,
                deepComments: document.getElementById('deep-comments').checked
            };
            monitorConfig = config;
            localStorage.setItem('moltbook_config', JSON.stringify(config));
        }
        
        let monitorConfig = loadConfig();
        
        // ========================================================================
        // CONFIG UI FUNCTIONS
        // ========================================================================
        function toggleConfig() {
            const content = document.getElementById('config-content');
            const btn = content.previousElementSibling.querySelector('.toggle-btn');
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                btn.textContent = '▼ Expand';
            } else {
                content.classList.add('expanded');
                btn.textContent = '▲ Collapse';
            }
        }
        
        function renderKeywords() {
            const list = document.getElementById('keyword-list');
            list.innerHTML = monitorConfig.keywords.map((kw, i) => `
                <span class="keyword-chip">
                    ${esc(kw)}
                    <span class="remove-kw" onclick="removeKeyword(${i})">×</span>
                </span>
            `).join('');
            document.getElementById('kw-count').textContent = monitorConfig.keywords.length;
        }
        
        function renderSubmolts() {
            const list = document.getElementById('submolt-list');
            list.innerHTML = monitorConfig.submolts.map((sub, i) => `
                <span class="keyword-chip submolt-chip">
                    m/${esc(sub)}
                    <span class="remove-kw" onclick="removeSubmolt(${i})">×</span>
                </span>
            `).join('');
            document.getElementById('sub-count').textContent = monitorConfig.submolts.length;
        }
        
        function addKeyword() {
            const input = document.getElementById('new-keyword');
            const kw = input.value.trim().toLowerCase();
            if (kw && !monitorConfig.keywords.includes(kw)) {
                monitorConfig.keywords.push(kw);
                saveConfig();
                renderKeywords();
            }
            input.value = '';
        }
        
        function removeKeyword(idx) {
            monitorConfig.keywords.splice(idx, 1);
            saveConfig();
            renderKeywords();
        }
        
        function resetKeywords() {
            if (confirm('Reset keywords to defaults?')) {
                monitorConfig.keywords = [...DEFAULT_KEYWORDS];
                saveConfig();
                renderKeywords();
            }
        }
        
        function addSubmolt() {
            const input = document.getElementById('new-submolt');
            let sub = input.value.trim().toLowerCase();
            if (sub.startsWith('m/')) sub = sub.slice(2);
            if (sub && !monitorConfig.submolts.includes(sub)) {
                monitorConfig.submolts.push(sub);
                saveConfig();
                renderSubmolts();
            }
            input.value = '';
        }
        
        function removeSubmolt(idx) {
            monitorConfig.submolts.splice(idx, 1);
            saveConfig();
            renderSubmolts();
        }
        
        function resetSubmolts() {
            if (confirm('Reset submolts to defaults?')) {
                monitorConfig.submolts = [...DEFAULT_SUBMOLTS];
                saveConfig();
                renderSubmolts();
            }
        }
        
        function updateThreshold() {
            const val = document.getElementById('fuzzy-threshold').value;
            document.getElementById('threshold-val').textContent = (val / 100).toFixed(2);
            saveConfig();
        }
        
        function initConfigUI() {
            renderKeywords();
            renderSubmolts();
            document.getElementById('fuzzy-enabled').checked = monitorConfig.fuzzyEnabled;
            document.getElementById('fuzzy-threshold').value = monitorConfig.fuzzyThreshold * 100;
            document.getElementById('threshold-val').textContent = monitorConfig.fuzzyThreshold.toFixed(2);
            document.getElementById('scan-submolts').checked = monitorConfig.scanSubmolts;
            document.getElementById('deep-comments').checked = monitorConfig.deepComments;
        }

        // ========================================================================
        // FUZZY MATCHING (Client-side)
        // ========================================================================
        function levenshteinDistance(a, b) {
            const matrix = [];
            for (let i = 0; i <= b.length; i++) matrix[i] = [i];
            for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
            for (let i = 1; i <= b.length; i++) {
                for (let j = 1; j <= a.length; j++) {
                    if (b.charAt(i-1) === a.charAt(j-1)) {
                        matrix[i][j] = matrix[i-1][j-1];
                    } else {
                        matrix[i][j] = Math.min(
                            matrix[i-1][j-1] + 1,
                            matrix[i][j-1] + 1,
                            matrix[i-1][j] + 1
                        );
                    }
                }
            }
            return matrix[b.length][a.length];
        }
        
        function fuzzyMatchClient(needle, haystack, threshold = 0.75) {
            if (!needle || !haystack) return false;
            const needleLower = needle.toLowerCase();
            const haystackLower = haystack.toLowerCase();
            
            // Exact match
            if (haystackLower.includes(needleLower)) return true;
            
            // For short needles, only exact
            if (needleLower.length < 3) return false;
            
            // Check words
            const words = haystackLower.match(/\\b\\w+\\b/g) || [];
            for (const word of words) {
                if (word.length < needleLower.length - 2) continue;
                const dist = levenshteinDistance(needleLower, word);
                const maxLen = Math.max(needleLower.length, word.length);
                const similarity = 1 - (dist / maxLen);
                if (similarity >= threshold) return true;
            }
            
            return false;
        }
        
        function checkTextForKeywordsClient(text, keywords, fuzzy = true, threshold = 0.75) {
            if (!text) return null;
            for (const kw of keywords) {
                if (fuzzy) {
                    if (fuzzyMatchClient(kw, text, threshold)) return kw;
                } else {
                    if (text.toLowerCase().includes(kw.toLowerCase())) return kw;
                }
            }
            return null;
        }

        // ========================================================================
        // CORE STATE
        // ========================================================================
        let myKey = localStorage.getItem('moltbook_api_key') || '';

        function setMyKey(k) {
            myKey = (k || '').trim();
            if (myKey) localStorage.setItem('moltbook_api_key', myKey);
            else localStorage.removeItem('moltbook_api_key');
        }

        function getAuthHeaders() {
            return myKey ? { 'X-API-Key': myKey } : {};
        }

        function decodeHexMaybe(s) {
            if (!s) return '';
            const str = String(s).trim();
            if (!str || str.length % 2 !== 0) return str;
            if (!/^[0-9a-fA-F]{6,128}$/.test(str)) return str;
            try {
                let out = '';
                for (let i = 0; i < str.length; i += 2) {
                    out += String.fromCharCode(parseInt(str.slice(i, i + 2), 16));
                }
                if (/^[\x20-\x7E]+$/.test(out)) return out;
            } catch (e) {}
            return str;
        }

        // All loaded posts pool (for client-side search)
        let allLoadedPosts = new Map(); // id -> post
        
        let feedState = {
            hot: { posts: [], offset: 0, hasMore: true, loaded: false },
            new: { posts: [], offset: 0, hasMore: true, loaded: false },
            top: { posts: [], offset: 0, hasMore: true, loaded: false }
        };
        let tabLoaded = { flag: false, subs: false };
        let activeTab = 'hot';
        let requestInProgress = false;

        // ========================================================================
        // UTILITIES
        // ========================================================================
        function esc(t) { if (!t) return ''; const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
        function fmt(n) { if (n == null) return '0'; if (n >= 1000000) return (n/1000000).toFixed(1) + 'M'; if (n >= 1000) return (n/1000).toFixed(1) + 'k'; return String(n); }

        function setStatus(status, text) {
            const dot = document.getElementById('status-dot');
            document.getElementById('status-text').textContent = text;
            dot.className = 'status-dot ' + status;
        }

        function updateStats(stats) {
            if (stats) {
                document.getElementById('stat-ok').textContent = stats.success || 0;
                document.getElementById('stat-fail').textContent = stats.failed || 0;
                document.getElementById('stat-timeout').textContent = stats.timeouts || 0;
            }
        }

        function showErr(msg) {
            document.getElementById('error-banner').style.display = 'flex';
            document.getElementById('error-msg').textContent = msg;
        }
        function hideErr() { document.getElementById('error-banner').style.display = 'none'; }

        function displayAuthorName(p) {
            const raw = p?.author?.name;
            if (raw && raw !== 'Anonymous') {
                const dec = decodeHexMaybe(raw);
                return dec || raw;
            }
            const title = p?.title || '';
            const m = title.match(/^@([A-Za-z0-9_-]{2,32})\b/);
            if (m) return '@' + m[1] + ' (title)';
            return raw || 'Anonymous';
        }
        
        function updateSearchPoolCount() {
            document.getElementById('search-pool-count').textContent = allLoadedPosts.size;
        }
        
        function addPostsToPool(posts) {
            for (const p of posts) {
                if (p.id && !allLoadedPosts.has(p.id)) {
                    allLoadedPosts.set(p.id, p);
                }
            }
            updateSearchPoolCount();
        }

        function showTab(id, btnEl=null) {
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(id).classList.add('active');

            if (btnEl) btnEl.classList.add('active');
            else {
                const tabs = Array.from(document.querySelectorAll('.tab'));
                const match = tabs.find(t => (t.getAttribute('onclick') || '').includes(`showTab('${id}'`));
                if (match) match.classList.add('active');
            }

            activeTab = id;

            if (['hot', 'new', 'top'].includes(id) && !feedState[id].loaded) {
                loadFeed(id);
            } else if (id === 'subs' && !tabLoaded.subs) {
                loadSubs();
            } else if (id === 'grammar') {
                loadGrammar();
            } else if (id === 'logs') {
                refreshLog();
            } else if (id === 'search') {
                updateSearchPoolCount();
            }
        }

        // ========================================================================
        // RENDER FUNCTIONS
        // ========================================================================
        function renderPost(p, flagged = false, commentFlagged = false, source = null) {
            const content = p.content ? p.content.substring(0, 180) + (p.content.length > 180 ? '...' : '') : '';
            const author = displayAuthorName(p);
            const sub = p.submolt?.name || p.submolt || 'general';
            const id = p.id || '';
            const karma = (p.upvotes || 0) - (p.downvotes || 0);
            
            let flagClass = '';
            if (flagged) flagClass = 'flagged';
            else if (commentFlagged) flagClass = 'comment-flagged';
            
            let footExtra = '';
            if (p._kw) footExtra += `<span class="kw-tag${p._fuzzy ? ' fuzzy' : ''}">${esc(p._kw)}${p._fuzzy ? ' ~' : ''}</span>`;
            if (p._comment_kw) footExtra += `<span class="kw-tag comment">💬 ${esc(p._comment_kw)}</span>`;
            if (source) footExtra += `<span class="source-tag">${esc(source)}</span>`;
            
            return `
                <div class="post-card ${flagClass}" onclick='openPost("${id}")'>
                    <div class="post-head">
                        <span class="author" onclick="event.stopPropagation(); findAgentByName('${esc(author.replace(' (title)',''))}');">🤖 ${esc(author)}</span>
                        <span class="submolt-tag" onclick="event.stopPropagation(); loadSubPosts('${esc(sub)}')" title="View m/${esc(sub)}">m/${esc(sub)}</span>
                    </div>
                    <div class="post-title">${flagged || commentFlagged ? '⚠️ ' : ''}${esc(p.title) || 'Untitled'}</div>
                    <div class="post-body">${esc(content)}</div>
                    <div class="post-foot">
                        <span class="karma">⬆️ ${fmt(karma)}</span>
                        <span class="comments-count">💬 ${p.comment_count || 0}</span>
                        <span class="submolt-tag" onclick="event.stopPropagation(); loadSubPosts('${esc(sub)}')" style="font-size:0.65em;">m/${esc(sub)}</span>
                        ${footExtra}
                    </div>
                </div>
            `;
        }

        function renderSub(s) {
            const name = s.name || 'unknown';
            return `
                <div class="submolt-card" onclick="loadSubPosts('${esc(name)}')">
                    <div>
                        <div class="submolt-name">m/${esc(name)}</div>
                        <div class="submolt-desc">${esc(s.description) || ''}</div>
                    </div>
                    <div class="submolt-count">${fmt(s.subscriber_count || 0)}</div>
                </div>
            `;
        }

        function renderAgent(a) {
            const owner = a.owner || {};
            const xHandleRaw = owner.x_handle || owner.xHandle || '';
            const xHandle = xHandleRaw;
            const xHandleDecoded = decodeHexMaybe(xHandleRaw);
            const showDecoded = xHandleDecoded && xHandleDecoded !== xHandleRaw;
            const xVerified = (owner.x_verified ?? owner.xVerified) === true;

            const xInfo = xHandle ? `
                <div class="x-info">
                    𝕏 <a href="https://x.com/${esc(xHandle)}" target="_blank">@${esc(xHandle)}</a> 
                    ${xVerified ? '✓ verified' : '<span style="color:var(--yellow);">⚠️ not verified</span>'}
                    ${showDecoded ? `<span style="color:var(--muted); font-size:0.9em;"> (decodes to: ${esc(xHandleDecoded)})</span>` : ''}
                </div>
            ` : '';

            let verifiedPill, verificationNote = '';
            if (xVerified) {
                verifiedPill = `<span class="pill ok">VERIFIED</span>`;
            } else if (xHandle) {
                verifiedPill = `<span class="pill warn">NOT VERIFIED</span>`;
                verificationNote = `
                    <div style="margin-top:8px; padding:8px; background:rgba(234,179,8,0.1); border:1px solid var(--yellow); border-radius:5px; font-size:0.72em;">
                        <strong>⚠️ Verification Required for Comments</strong><br>
                        Your agent is claimed (linked to @${esc(xHandle)}) but not verified.<br>
                        → Go to <a href="https://moltbook.com" target="_blank" style="color:var(--cyan);">moltbook.com</a> and complete the verification step.
                    </div>
                `;
            } else {
                verifiedPill = `<span class="pill err">UNCLAIMED</span>`;
                verificationNote = `
                    <div style="margin-top:8px; padding:8px; background:rgba(239,68,68,0.1); border:1px solid var(--red); border-radius:5px; font-size:0.72em;">
                        <strong>❌ Unclaimed Agent</strong><br>
                        This agent is not linked to any X account.<br>
                        → Go to <a href="https://moltbook.com" target="_blank" style="color:var(--cyan);">moltbook.com</a> to claim and verify your agent.
                    </div>
                `;
            }

            return `
                <div class="agent-card">
                    <div class="agent-head">
                        <div class="agent-avatar">🤖</div>
                        <div>
                            <div class="agent-name">${esc(a.name || 'Unknown')}${verifiedPill}</div>
                            <div class="agent-bio">${esc(a.description) || 'No bio'}</div>
                        </div>
                    </div>
                    <div class="agent-stats">
                        <div class="agent-stat"><div class="agent-stat-val">${fmt(a.karma || 0)}</div><div class="agent-stat-lbl">Karma</div></div>
                        <div class="agent-stat"><div class="agent-stat-val">${fmt(a.follower_count || 0)}</div><div class="agent-stat-lbl">Followers</div></div>
                        <div class="agent-stat"><div class="agent-stat-val">${fmt(a.following_count || 0)}</div><div class="agent-stat-lbl">Following</div></div>
                        <div class="agent-stat"><div class="agent-stat-val">${a.post_count || '?'}</div><div class="agent-stat-lbl">Posts</div></div>
                    </div>
                    ${xInfo}
                    ${verificationNote}
                </div>
            `;
        }

        function renderAuthorBox(author, title='') {
            if (!author) return '';
            const p = {author, title};
            const name = displayAuthorName(p);
            return `
                <div class="author-box">
                    <div class="author-box-head">
                        <div class="author-box-avatar">🤖</div>
                        <div>
                            <div class="author-box-name" onclick="closeModal(); findAgentByName('${esc(name.replace(' (title)',''))}')">${esc(name)}</div>
                            <div class="author-box-bio">${esc(author.description || '')}</div>
                        </div>
                    </div>
                    <div class="author-box-stats">
                        Karma: <span>${fmt(author.karma || 0)}</span> •
                        Followers: <span>${fmt(author.follower_count || 0)}</span>
                    </div>
                </div>
            `;
        }

        function renderComment(c, flaggedKeywords = []) {
            const author = c.author?.name || 'Anonymous';
            const karma = (c.upvotes || 0) - (c.downvotes || 0);
            const replies = c.replies || [];
            const content = c.content || '';
            
            const isFlagged = flaggedKeywords.some(fc => fc.content === content.substring(0, 200));
            
            return `
                <div class="comment ${isFlagged ? 'flagged' : ''}">
                    <span class="comment-author" onclick="findAgentByName('${esc(author)}')">${esc(author)}</span>
                    <span class="comment-meta"> • ⬆️ ${karma} ${isFlagged ? '• <span style="color:var(--red);">⚠️ FLAGGED</span>' : ''}</span>
                    <div class="comment-text">${esc(content)}</div>
                    ${replies.length ? `<div class="comment-replies">${replies.map(r => renderComment(r, flaggedKeywords)).join('')}</div>` : ''}
                </div>
            `;
        }

        function renderError(msg, canRetry = true) {
            return `
                <div class="error-state">
                    <div class="icon">⚠️</div>
                    <div class="msg">${esc(msg)}</div>
                    ${canRetry ? '<button class="btn orange" onclick="refreshCurrent()">Retry</button>' : ''}
                </div>
            `;
        }

        // ========================================================================
        // FEED LOADING
        // ========================================================================
        async function loadFeed(sort, append = false) {
            if (requestInProgress) return;
            requestInProgress = true;

            const state = feedState[sort];
            const el = document.getElementById(sort + '-grid');
            const moreBtn = document.getElementById(sort + '-more');

            if (!append) {
                el.innerHTML = '<div class="loading">Loading...</div>';
                state.posts = [];
                state.offset = 0;
            } else {
                moreBtn.textContent = 'Loading...';
                moreBtn.classList.add('loading');
                moreBtn.disabled = true;
            }

            setStatus('loading', `Loading ${sort}...`);

            try {
                const limit = append ? ''' + str(LOAD_MORE_LIMIT) + ''' : ''' + str(INITIAL_LIMIT) + ''';
                const r = await fetch(`/api/feed?sort=${sort}&limit=${limit}&offset=${state.offset}`, { headers: getAuthHeaders() });
                const d = await r.json();

                updateStats(d._stats);

                if (d.success && d.posts?.length) {
                    state.posts = state.posts.concat(d.posts);
                    state.offset += d.posts.length;
                    state.hasMore = d.has_more !== false;
                    state.loaded = true;
                    
                    // Add to search pool
                    addPostsToPool(d.posts);

                    el.innerHTML = state.posts.map(p => renderPost(p)).join('');

                    moreBtn.style.display = state.hasMore ? 'block' : 'none';
                    moreBtn.textContent = `Load More (${state.posts.length} loaded)`;
                    moreBtn.classList.remove('loading');
                    moreBtn.disabled = false;

                    if (sort === 'hot') {
                        document.getElementById('s-posts').textContent = d.count || state.posts.length;
                        const agents = new Set(state.posts.map(p => displayAuthorName(p)).filter(Boolean));
                        document.getElementById('s-agents').textContent = agents.size;
                    }

                    setStatus('ok', `Loaded ${state.posts.length} posts`);
                    hideErr();
                } else {
                    if (!append) el.innerHTML = renderError(d.error || 'No posts returned');
                    moreBtn.style.display = 'none';
                    setStatus('err', d.error || 'Failed');
                }
            } catch (e) {
                if (!append) el.innerHTML = renderError(e.message);
                setStatus('err', e.message);
                showErr(e.message);
            }

            requestInProgress = false;
        }

        function loadMore(sort) { loadFeed(sort, true); }

        // ========================================================================
        // SUBMOLTS
        // ========================================================================
        async function loadSubs() {
            const el = document.getElementById('subs-grid');
            el.innerHTML = '<div class="loading">Loading submolts...</div>';
            setStatus('loading', 'Loading submolts...');

            try {
                const r = await fetch('/api/submolts', { headers: getAuthHeaders() });
                const d = await r.json();
                updateStats(d._stats);

                if (d.success && d.submolts?.length) {
                    el.innerHTML = d.submolts.map(s => renderSub(s)).join('');
                    document.getElementById('s-subs').textContent = d.count || d.submolts.length;
                    tabLoaded.subs = true;
                    setStatus('ok', `${d.submolts.length} submolts`);
                } else {
                    el.innerHTML = renderError(d.error || 'No submolts');
                    setStatus('err', d.error || 'Failed');
                }
            } catch (e) {
                el.innerHTML = renderError(e.message);
                setStatus('err', e.message);
            }
        }

        async function loadSubPosts(name) {
            showTab('subs');
            document.getElementById('sub-posts-box').style.display = 'block';
            document.getElementById('sub-posts-title').innerHTML = `<a href="https://moltbook.com/m/${esc(name)}" target="_blank" style="color:var(--orange); text-decoration:none;">m/${esc(name)} ↗</a>`;
            const el = document.getElementById('sub-posts-grid');
            el.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const r = await fetch(`/api/submolt/${encodeURIComponent(name)}/posts`, { headers: getAuthHeaders() });
                const d = await r.json();
                if (d.success && d.posts?.length) {
                    addPostsToPool(d.posts);
                    el.innerHTML = d.posts.map(p => renderPost(p)).join('');
                }
                else el.innerHTML = `<p style="color:var(--muted);">${d.error || 'No posts'}</p>`;
            } catch (e) {
                el.innerHTML = renderError(e.message);
            }
        }

        // ========================================================================
        // PROGRESSIVE SCAN (Client-orchestrated, stoppable)
        // ========================================================================
        let scanRunning = false;
        let scanAbort = false;
        let flaggedPosts = [];
        let scannedCount = 0;
        let totalToScan = 0;
        
        function updateScanUI(status, scanned, flagged, progress) {
            document.getElementById('scan-status').textContent = status;
            document.getElementById('scan-stats').textContent = `${scanned} scanned | ${flagged} flagged`;
            document.getElementById('scan-bar').style.width = `${progress}%`;
        }
        
        function renderFlaggedGrid() {
            const el = document.getElementById('flag-grid');
            if (flaggedPosts.length === 0) {
                el.innerHTML = '<p style="color:var(--muted); text-align:center; padding:20px;">No flagged posts found (yet)</p>';
            } else {
                el.innerHTML = flaggedPosts.map(p => {
                    const hasTitleFlag = !!p._kw;
                    const hasCommentFlag = !!p._comment_kw;
                    return renderPost(p, hasTitleFlag, hasCommentFlag && !hasTitleFlag, p._source);
                }).join('');
            }
            document.getElementById('s-flagged').textContent = flaggedPosts.length;
        }
        
        async function startProgressiveScan() {
            if (scanRunning) return;
            
            scanRunning = true;
            scanAbort = false;
            flaggedPosts = [];
            scannedCount = 0;
            
            // UI setup
            document.getElementById('scan-start-btn').style.display = 'none';
            document.getElementById('scan-stop-btn').style.display = 'block';
            document.getElementById('scan-progress').style.display = 'block';
            document.getElementById('flag-grid').innerHTML = '';
            
            const keywords = monitorConfig.keywords;
            const threshold = monitorConfig.fuzzyThreshold;
            const useFuzzy = monitorConfig.fuzzyEnabled;
            const deepComments = monitorConfig.deepComments;
            const scanSubmolts = monitorConfig.scanSubmolts;
            const submolts = scanSubmolts ? monitorConfig.submolts : [];
            
            setStatus('loading', 'Scanning...');
            
            try {
                // PHASE 1: Fetch NEW posts
                updateScanUI('Fetching NEW posts...', 0, 0, 5);
                if (scanAbort) throw new Error('Stopped');
                
                const newResp = await fetch('/api/feed?sort=new&limit=40', { headers: getAuthHeaders() });
                const newData = await newResp.json();
                const newPosts = newData.posts || [];
                newPosts.forEach(p => p._source = 'new');
                
                if (scanAbort) throw new Error('Stopped');
                
                // PHASE 2: Fetch HOT posts
                updateScanUI('Fetching HOT posts...', 0, 0, 15);
                
                const hotResp = await fetch('/api/feed?sort=hot&limit=30', { headers: getAuthHeaders() });
                const hotData = await hotResp.json();
                const hotPosts = hotData.posts || [];
                hotPosts.forEach(p => p._source = 'hot');
                
                if (scanAbort) throw new Error('Stopped');
                
                // PHASE 3: Fetch submolt posts
                let submoltPosts = [];
                for (let i = 0; i < submolts.length && i < 3; i++) {
                    if (scanAbort) throw new Error('Stopped');
                    updateScanUI(`Fetching m/${submolts[i]}...`, 0, 0, 20 + i * 5);
                    
                    const subResp = await fetch(`/api/submolt/${encodeURIComponent(submolts[i])}/posts`, { headers: getAuthHeaders() });
                    const subData = await subResp.json();
                    const posts = subData.posts || [];
                    posts.forEach(p => p._source = `m/${submolts[i]}`);
                    submoltPosts = submoltPosts.concat(posts);
                }
                
                // Deduplicate
                const seen = new Set();
                const allPosts = [];
                for (const p of [...newPosts, ...hotPosts, ...submoltPosts]) {
                    if (p.id && !seen.has(p.id)) {
                        seen.add(p.id);
                        allPosts.push(p);
                    }
                }
                
                // Add to search pool
                addPostsToPool(allPosts);
                
                totalToScan = allPosts.length;
                updateScanUI(`Scanning ${totalToScan} posts...`, 0, 0, 35);
                
                // PHASE 4: Quick keyword scan (local, fast)
                const postsWithComments = [];
                
                for (let i = 0; i < allPosts.length; i++) {
                    if (scanAbort) throw new Error('Stopped');
                    
                    const p = allPosts[i];
                    const text = `${p.title || ''} ${p.content || ''}`;
                    const kw = checkTextForKeywordsClient(text, keywords, useFuzzy, threshold);
                    
                    if (kw) {
                        p._kw = kw;
                        p._fuzzy = useFuzzy && !text.toLowerCase().includes(kw.toLowerCase());
                        flaggedPosts.push(p);
                        renderFlaggedGrid();
                    } else if (deepComments && (p.comment_count || 0) > 0) {
                        postsWithComments.push(p);
                    }
                    
                    scannedCount++;
                    if (i % 10 === 0) {
                        updateScanUI(`Scanning posts... (${i+1}/${totalToScan})`, scannedCount, flaggedPosts.length, 35 + (i / totalToScan) * 30);
                    }
                }
                
                // PHASE 5: Deep comment scan (limited, one at a time)
                if (deepComments && postsWithComments.length > 0 && !scanAbort) {
                    // Sort by comment count, take top 10
                    postsWithComments.sort((a, b) => (b.comment_count || 0) - (a.comment_count || 0));
                    const toDeepScan = postsWithComments.slice(0, 10);
                    
                    for (let i = 0; i < toDeepScan.length; i++) {
                        if (scanAbort) throw new Error('Stopped');
                        
                        const p = toDeepScan[i];
                        updateScanUI(`Deep scanning comments... (${i+1}/${toDeepScan.length})`, scannedCount, flaggedPosts.length, 65 + (i / toDeepScan.length) * 30);
                        
                        try {
                            const resp = await fetch(`/api/post/${p.id}`, { headers: getAuthHeaders() });
                            const data = await resp.json();
                            
                            if (data.success && data.comments) {
                                // Scan comments client-side
                                const commentKw = scanCommentsClient(data.comments, keywords, useFuzzy, threshold);
                                if (commentKw) {
                                    p._comment_kw = commentKw;
                                    if (!flaggedPosts.find(fp => fp.id === p.id)) {
                                        flaggedPosts.push(p);
                                        renderFlaggedGrid();
                                    }
                                }
                            }
                        } catch (e) {
                            console.error('Comment fetch error:', e);
                        }
                    }
                }
                
                // Done
                updateScanUI('Complete!', scannedCount, flaggedPosts.length, 100);
                setStatus('ok', `${flaggedPosts.length} flagged from ${scannedCount} posts`);
                
            } catch (e) {
                if (e.message === 'Stopped') {
                    updateScanUI('Stopped by user', scannedCount, flaggedPosts.length, 0);
                    setStatus('warn', 'Scan stopped');
                } else {
                    updateScanUI(`Error: ${e.message}`, scannedCount, flaggedPosts.length, 0);
                    setStatus('err', e.message);
                }
            }
            
            // Cleanup UI
            scanRunning = false;
            document.getElementById('scan-start-btn').style.display = 'block';
            document.getElementById('scan-stop-btn').style.display = 'none';
            
            // Final render
            renderFlaggedGrid();
            tabLoaded.flag = true;
        }
        
        function stopScan() {
            scanAbort = true;
        }
        
        function scanCommentsClient(comments, keywords, fuzzy, threshold) {
            // Recursive comment scanner
            for (const c of comments) {
                const content = c.content || '';
                const kw = checkTextForKeywordsClient(content, keywords, fuzzy, threshold);
                if (kw) return kw;
                
                if (c.replies && c.replies.length) {
                    const replyKw = scanCommentsClient(c.replies, keywords, fuzzy, threshold);
                    if (replyKw) return replyKw;
                }
            }
            return null;
        }
        
        // Keep old function name for compatibility but redirect
        async function loadFlagged() {
            startProgressiveScan();
        }

        // ========================================================================
        // CLIENT-SIDE SEARCH
        // ========================================================================
        function doClientSearch() {
            const q = document.getElementById('search-q').value.trim().toLowerCase();
            const el = document.getElementById('search-results');
            const useFuzzy = document.getElementById('search-fuzzy').checked;
            
            if (!q) { 
                el.innerHTML = '<p style="color:var(--muted);">Enter search term</p>'; 
                return; 
            }
            
            if (allLoadedPosts.size === 0) {
                el.innerHTML = '<p style="color:var(--muted);">No posts loaded yet. Load some feeds first.</p>';
                return;
            }
            
            setStatus('loading', 'Searching loaded posts...');
            
            const results = [];
            const threshold = monitorConfig.fuzzyThreshold;
            
            for (const [id, p] of allLoadedPosts) {
                const searchText = `${p.title || ''} ${p.content || ''} ${(p.author?.name) || ''}`.toLowerCase();
                
                let match = false;
                if (useFuzzy) {
                    match = fuzzyMatchClient(q, searchText, threshold);
                } else {
                    match = searchText.includes(q);
                }
                
                if (match) {
                    results.push(p);
                }
            }
            
            // Sort by karma
            results.sort((a, b) => ((b.upvotes || 0) - (b.downvotes || 0)) - ((a.upvotes || 0) - (a.downvotes || 0)));
            
            if (results.length > 0) {
                el.innerHTML = `<p style="color:var(--green); margin-bottom:8px; font-size:0.8em;">Found ${results.length} matching posts</p>` +
                    results.slice(0, 50).map(p => renderPost(p)).join('');
                setStatus('ok', `${results.length} results`);
            } else {
                el.innerHTML = '<p style="color:var(--muted);">No matches found. Try loading more posts or different search terms.</p>';
                setStatus('warn', 'No results');
            }
        }
        
        document.getElementById('search-q').addEventListener('keypress', e => { if (e.key === 'Enter') doClientSearch(); });

        // ========================================================================
        // AGENT SEARCH (now client-side first, then API fallback)
        // ========================================================================
        function findAgentByName(name) {
            showTab('agent');
            document.getElementById('agent-q').value = name;
            findAgent();
        }

        async function findAgent() {
            const name = document.getElementById('agent-q').value.trim();
            const el = document.getElementById('agent-results');
            if (!name) { el.innerHTML = '<p style="color:var(--muted);">Enter name</p>'; return; }

            el.innerHTML = '<div class="loading">Finding agent...</div>';
            setStatus('loading', 'Finding agent...');

            // First, search loaded posts for agent
            const nameLower = name.toLowerCase();
            const agentPosts = [];
            for (const [id, p] of allLoadedPosts) {
                const authorName = (p.author?.name || '').toLowerCase();
                if (authorName === nameLower || authorName.includes(nameLower)) {
                    agentPosts.push(p);
                }
            }

            // Then try API
            try {
                const r = await fetch(`/api/agent/${encodeURIComponent(name)}`, { headers: getAuthHeaders() });
                const d = await r.json();
                updateStats(d._stats);

                if (d.success && d.agent) {
                    // Merge API posts with locally found posts
                    const allAgentPosts = [...agentPosts];
                    if (d.posts) {
                        for (const p of d.posts) {
                            if (!allAgentPosts.find(ap => ap.id === p.id)) {
                                allAgentPosts.push(p);
                            }
                        }
                    }
                    addPostsToPool(allAgentPosts);
                    
                    let html = renderAgent(d.agent);
                    if (allAgentPosts.length) {
                        html += `<h3 style="color:var(--orange); margin:8px 0 5px; font-size:0.9em;">Posts (${allAgentPosts.length})</h3>`;
                        html += `<div class="grid">${allAgentPosts.slice(0, 15).map(p => renderPost(p)).join('')}</div>`;
                    }
                    el.innerHTML = html;
                    setStatus('ok', 'Found');
                } else if (agentPosts.length > 0) {
                    // API failed but we have local posts
                    const inferredAgent = { name: agentPosts[0].author?.name || name, post_count: agentPosts.length };
                    let html = renderAgent(inferredAgent);
                    html += `<h3 style="color:var(--orange); margin:8px 0 5px; font-size:0.9em;">Posts from loaded data (${agentPosts.length})</h3>`;
                    html += `<div class="grid">${agentPosts.slice(0, 15).map(p => renderPost(p)).join('')}</div>`;
                    el.innerHTML = html;
                    setStatus('ok', 'Found in loaded posts');
                } else {
                    el.innerHTML = `<p style="color:var(--muted);">${d.error || 'Not found'}. Try loading more posts.</p>`;
                    setStatus('warn', 'Not found');
                }
            } catch (e) {
                if (agentPosts.length > 0) {
                    const inferredAgent = { name: agentPosts[0].author?.name || name, post_count: agentPosts.length };
                    let html = renderAgent(inferredAgent);
                    html += `<h3 style="color:var(--orange); margin:8px 0 5px; font-size:0.9em;">Posts from loaded data (${agentPosts.length})</h3>`;
                    html += `<div class="grid">${agentPosts.slice(0, 15).map(p => renderPost(p)).join('')}</div>`;
                    el.innerHTML = html;
                    setStatus('ok', 'Found in loaded posts');
                } else {
                    el.innerHTML = renderError(e.message);
                    setStatus('err', e.message);
                }
            }
        }
        document.getElementById('agent-q').addEventListener('keypress', e => { if (e.key === 'Enter') findAgent(); });

        // ========================================================================
        // MY AGENT
        // ========================================================================
        async function loadMyAgent() {
            const k = document.getElementById('my-key').value.trim();
            const el = document.getElementById('mybot-results');
            if (!k) { el.innerHTML = '<p style="color:var(--red);">API key required</p>'; return; }
            setMyKey(k);

            el.innerHTML = '<div class="loading">Loading profile + status...</div>';
            try {
                const r = await fetch('/api/me', { headers: {'X-API-Key': myKey} });
                const d = await r.json();
                updateStats(d._stats);

                if (d.success && d.agent) {
                    let html = renderAgent(d.agent);
                    
                    if (d.status_check) {
                        const sc = d.status_check;
                        if (sc.inconsistent) {
                            html += `<div class="banner error">
                                <span>⚠️</span>
                                <span><strong>API INCONSISTENCY DETECTED:</strong> /agents/status says "${esc(sc.status)}" but other endpoints fail. 
                                This is a Moltbook API bug - commenting likely won't work until fixed.</span>
                            </div>`;
                        } else {
                            html += `<div class="banner success">
                                <span>✓</span>
                                <span>Status: ${esc(sc.status)} | Agent: ${esc(sc.agent_name || 'N/A')}</span>
                            </div>`;
                        }
                    }
                    
                    if (d.hint) {
                        html += `<div class="banner warning"><span>⚠️</span><span>${esc(d.hint)}</span></div>`;
                    }
                    if (d.posts?.length) {
                        addPostsToPool(d.posts);
                        html += `<h3 style="color:var(--orange); margin:8px 0 5px; font-size:0.9em;">Your Posts</h3>`;
                        html += `<div class="grid">${d.posts.map(p => renderPost(p)).join('')}</div>`;
                    }
                    el.innerHTML = html;
                    refreshCurrent();
                } else {
                    el.innerHTML = `<div class="banner error"><span>❌</span><span>${esc(d.error || 'Failed')}</span></div>`;
                    if (d.status_check) {
                        el.innerHTML += `<pre class="diag">${esc(JSON.stringify(d.status_check, null, 2))}</pre>`;
                    }
                }
            } catch (e) {
                el.innerHTML = renderError(e.message);
            }
        }

        // ========================================================================
        // POST MODAL
        // ========================================================================
        async function openPost(postId) {
            if (!postId) return;
            document.getElementById('modal').style.display = 'flex';
            document.getElementById('modal-body').innerHTML = '<div class="loading">Loading post...</div>';

            try {
                const r = await fetch(`/api/post/${postId}`, { headers: getAuthHeaders() });
                const d = await r.json();
                updateStats(d._stats);

                if (d.success && d.post) {
                    const p = d.post;
                    const author = p.author || {};
                    const sub = p.submolt?.name || 'general';
                    const karma = (p.upvotes || 0) - (p.downvotes || 0);
                    const comments = d.comments || [];
                    const authorName = displayAuthorName({author: author, title: p.title});
                    const flaggedComments = d.flagged_comments || [];

                    let flaggedCommentsHtml = '';
                    if (flaggedComments.length > 0) {
                        flaggedCommentsHtml = `
                            <div class="banner warning" style="margin-top:8px;">
                                <span>⚠️</span>
                                <span><strong>${flaggedComments.length}</strong> flagged comment(s) detected:</span>
                            </div>
                            ${flaggedComments.map(fc => `
                                <div class="flagged-comment-item">
                                    <span class="fc-author">${esc(fc.author)}</span>: 
                                    "${esc(fc.content.substring(0, 100))}..." 
                                    <span class="fc-kw">[${esc(fc.keyword)}]</span>
                                </div>
                            `).join('')}
                        `;
                    }

                    document.getElementById('modal-body').innerHTML = `
                        <div class="modal-title">${esc(p.title) || 'Post'}</div>
                        <div class="modal-meta">
                            <span class="author" onclick="closeModal(); findAgentByName('${esc(authorName.replace(' (title)',''))}');">🤖 ${esc(authorName)}</span>
                            <span class="submolt-tag" onclick="closeModal(); loadSubPosts('${esc(sub)}')" style="cursor:pointer;">m/${esc(sub)}</span>
                            <span>⬆️ ${fmt(karma)}</span>
                            <span>💬 ${comments.length}</span>
                            <a href="https://moltbook.com/m/${esc(sub)}" target="_blank" style="color:var(--cyan); font-size:0.85em;">↗ View on Moltbook</a>
                        </div>
                        <div class="modal-content">${esc(p.content) || 'No content'}</div>

                        ${renderAuthorBox(author, p.title)}
                        
                        ${flaggedCommentsHtml}

                        <div class="comment-form">
                            <h4>💬 Add Comment</h4>
                            <textarea id="c-text" placeholder="Comment..."></textarea>
                            <div class="row">
                                <input type="password" id="c-key" placeholder="API Key" value="${esc(myKey)}">
                                <button onclick="postComment('${postId}')">Post</button>
                            </div>
                            <div id="c-result" style="margin-top:4px; font-size:0.78em;"></div>
                        </div>

                        <div class="comments-section">
                            <h4>💬 Comments (${comments.length})</h4>
                            ${comments.length ? comments.map(c => renderComment(c, flaggedComments)).join('') : '<p style="color:var(--muted); font-size:0.82em;">No comments</p>'}
                        </div>
                    `;
                } else {
                    document.getElementById('modal-body').innerHTML = renderError(d.error || 'Failed to load');
                }
            } catch (e) {
                document.getElementById('modal-body').innerHTML = renderError(e.message);
            }
        }

        async function postComment(postId) {
            const text = document.getElementById('c-text').value.trim();
            const key = document.getElementById('c-key').value.trim();
            const el = document.getElementById('c-result');
            if (!key) { el.innerHTML = '<span style="color:var(--red);">API key required</span>'; return; }
            if (!text) { el.innerHTML = '<span style="color:var(--red);">Comment required</span>'; return; }
            setMyKey(key);

            el.innerHTML = '<span style="color:var(--dim);">Posting...</span>';
            try {
                const r = await fetch('/api/comment', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-API-Key': myKey},
                    body: JSON.stringify({post_id: postId, content: text})
                });
                const d = await r.json();
                updateStats(d._stats);

                if (d.success) {
                    el.innerHTML = '<span style="color:var(--green);">✅ Posted!</span>';
                    document.getElementById('c-text').value = '';
                    setTimeout(() => openPost(postId), 800);
                } else {
                    let msg = d.error || 'Comment failed';
                    el.innerHTML = `<span style="color:var(--red);">Error: ${esc(msg)}</span>`;
                    if (d.hint) {
                        el.innerHTML += `<div class="banner warning" style="margin-top:6px;"><span>⚠️</span><span>${esc(d.hint)}</span></div>`;
                    }
                    if (d.diagnostics) {
                        el.innerHTML += `<pre class="diag">${esc(JSON.stringify(d.diagnostics, null, 2))}</pre>`;
                    }
                }
            } catch (e) {
                el.innerHTML = `<span style="color:var(--red);">Error: ${esc(e.message)}</span>`;
            }
        }

        function closeModal() { document.getElementById('modal').style.display = 'none'; }
        document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

        // ========================================================================
        // REGISTER & CREATE POST
        // ========================================================================
        async function registerAgent() {
            const name = document.getElementById('reg-name').value.trim();
            const desc = document.getElementById('reg-desc').value.trim();
            const el = document.getElementById('reg-result');
            if (!name) { el.innerHTML = '<p style="color:var(--red);">Name required</p>'; return; }

            el.innerHTML = '<div class="loading">Registering...</div>';
            try {
                const r = await fetch('/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name, description: desc})
                });
                const d = await r.json();
                if (d.success) {
                    let html = `<div class="banner success" style="display:block;">`;
                    html += `<div style="font-weight:bold; font-size:1.1em; margin-bottom:4px;">✅ Registration Successful!</div>`;
                    html += `<div style="margin-bottom:8px;">API Key: <code style="background:rgba(0,0,0,0.3); user-select:all;">${esc(d.api_key)}</code> <span style="color:var(--red); font-weight:bold;">(SAVE THIS)</span></div>`;
                    
                    if (d.claim_url) {
                        html += `<div style="background:rgba(255,255,255,0.1); padding:8px; border-radius:4px; margin-top:8px;">`;
                        html += `<strong>👉 Next Step: Claim Your Agent</strong><br>`;
                        html += `Send this URL to your human:<br>`;
                        html += `<a href="${esc(d.claim_url)}" target="_blank" style="color:white; text-decoration:underline; word-break:break-all;">${esc(d.claim_url)}</a>`;
                        
                        if (d.verification_code) {
                            html += `<br><br>Verification Code: <strong style="color:white; background:var(--orange); padding:2px 6px; border-radius:4px;">${esc(d.verification_code)}</strong>`;
                        }
                        html += `</div>`;
                    }
                    html += `</div>`;
                    el.innerHTML = html;
                } else {
                    el.innerHTML = `<p style="color:var(--red);">${esc(d.error || 'Failed')}</p>`;
                }
            } catch (e) {
                el.innerHTML = renderError(e.message, false);
            }
        }

        async function createPost() {
            const key = document.getElementById('p-key').value.trim();
            const sub = document.getElementById('p-sub').value.trim() || 'general';
            const title = document.getElementById('p-title').value.trim();
            const content = document.getElementById('p-content').value.trim();
            const el = document.getElementById('post-result');

            if (!key) { el.innerHTML = '<p style="color:var(--red);">API key required</p>'; return; }
            if (!title) { el.innerHTML = '<p style="color:var(--red);">Title required</p>'; return; }

            setMyKey(key);

            el.innerHTML = '<div class="loading">Posting...</div>';
            try {
                const r = await fetch('/api/post', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-API-Key': myKey},
                    body: JSON.stringify({submolt: sub, title, content})
                });
                const d = await r.json();
                updateStats(d._stats);

                if (d.success) {
                    el.innerHTML = `<div class="banner success">✅ Posted! ID: ${esc(d.post_id || 'OK')}</div>`;
                    document.getElementById('p-title').value = '';
                    document.getElementById('p-content').value = '';
                    feedState.new.loaded = false;
                    if (activeTab === 'new') loadFeed('new');
                } else {
                    el.innerHTML = `<div class="banner error"><span>❌</span><span>${esc(d.error || 'Failed')}</span></div>`;
                    if (d.hint) el.innerHTML += `<div class="banner warning"><span>⚠️</span><span>${esc(d.hint)}</span></div>`;
                    if (d.diagnostics) el.innerHTML += `<pre class="diag">${esc(JSON.stringify(d.diagnostics, null, 2))}</pre>`;
                }
            } catch (e) {
                el.innerHTML = renderError(e.message, false);
            }
        }

        // ========================================================================
        // GRAMMAR & LOGS
        // ========================================================================
        async function loadGrammar() {
            try {
                const r = await fetch('/api/grammar');
                const d = await r.json();

                document.getElementById('grammar-working').innerHTML = d.working.map(e => `
                    <div class="endpoint-item ok">
                        <strong>${esc(e.endpoint)}</strong>
                        <div class="endpoint-note">${esc(e.notes)}</div>
                    </div>
                `).join('');

                document.getElementById('grammar-blocked').innerHTML = d.blocked.map(e => `
                    <div class="endpoint-item blocked">
                        <strong>${esc(e.endpoint)}</strong>
                        <div class="endpoint-note">${esc(e.workaround)}</div>
                    </div>
                `).join('');
            } catch (e) { console.error(e); }
        }

        async function refreshLog() {
            const el = document.getElementById('log-content');
            try {
                const r = await fetch('/api/log');
                const d = await r.json();
                updateStats(d._stats);
                if (d.entries?.length) {
                    el.innerHTML = d.entries.slice().reverse().slice(0, 80).map(e => `
                        <div class="log-entry ${e.level}">
                            <span style="color:var(--muted);">${esc(e.timestamp)}</span>
                            <span style="color:${e.level === 'ERROR' || e.level === 'TIMEOUT' ? 'var(--red)' : e.level === 'SUCCESS' ? 'var(--green)' : 'var(--blue)'};">[${esc(e.level)}]</span>
                            ${esc(e.message)}
                        </div>
                    `).join('');
                } else {
                    el.innerHTML = '<p style="color:var(--muted);">No logs</p>';
                }
            } catch (e) { el.innerHTML = `<p style="color:var(--red);">${esc(e.message)}</p>`; }
        }

        function refreshCurrent() {
            if (['hot', 'new', 'top'].includes(activeTab)) {
                feedState[activeTab].loaded = false;
                feedState[activeTab].posts = [];
                feedState[activeTab].offset = 0;
                loadFeed(activeTab);
            } else if (activeTab === 'flag') {
                tabLoaded.flag = false;
                loadFlagged();
            } else if (activeTab === 'subs') {
                tabLoaded.subs = false;
                loadSubs();
            } else if (activeTab === 'logs') {
                refreshLog();
            }
        }

        // ========================================================================
        // INIT
        // ========================================================================
        document.getElementById('my-key').value = myKey;
        initConfigUI();
        loadFeed('hot');
    </script>
</body>
</html>
'''

# ============================================================================
# API GRAMMAR
# ============================================================================
API_GRAMMAR = {
    "working": [
        {"endpoint": "GET /posts", "notes": "Params: sort, limit, offset, submolt"},
        {"endpoint": "GET /posts/{id}", "notes": "Returns post + comments + author"},
        {"endpoint": "POST /posts", "notes": "Create post (auth)"},
        {"endpoint": "POST /posts/{id}/comments", "notes": "Create comment (auth; see notes below)"},
        {"endpoint": "GET /submolts", "notes": "List all submolts"},
        {"endpoint": "GET /search?q=", "notes": "Search posts (unreliable - use client-side)"},
        {"endpoint": "POST /agents/register", "notes": "Register agent"},
        {"endpoint": "GET /agents/me", "notes": "Your profile (auth)"},
        {"endpoint": "GET /agents/status", "notes": "Claim status (auth)"},
    ],
    "blocked": [
        {"endpoint": "GET /agents/{name}", "workaround": "Varies; this viewer tries it then falls back to search"},
        {"endpoint": "GET /agents/me/identity-token", "workaround": "Returns 'Agent not found' even for claimed agents (API bug?)"},
        {"endpoint": "POST comments", "workaround": "Returns 401 even when /agents/status shows 'claimed' - API inconsistency"},
    ]
}

# ============================================================================
# FLASK ROUTES
# ============================================================================
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/log")
def api_log():
    return jsonify({"entries": list(debug_log), "_stats": request_stats})

@app.route("/api/grammar")
def api_grammar():
    return jsonify(API_GRAMMAR)

# ============================================================================
# FEED
# ============================================================================
@app.route("/api/feed")
def api_feed():
    sort = request.args.get("sort", "hot")
    limit = request.args.get("limit", INITIAL_LIMIT, type=int)
    offset = request.args.get("offset", 0, type=int)
    key = get_optional_api_key()

    log(f"FEED: sort={sort} limit={limit} offset={offset} auth={'yes' if key else 'no'}", "INFO")

    hdrs = auth_headers(key) if key else None
    result = api_request("posts", {"sort": sort, "limit": limit, "offset": offset}, headers=hdrs)
    posts = get_posts(result)

    return jsonify({
        "success": not result.get("_error"),
        "posts": posts,
        "count": result.get("count", len(posts)),
        "has_more": result.get("has_more", len(posts) == limit),
        "error": result.get("error"),
        "_elapsed": result.get("_elapsed"),
        "_stats": request_stats
    })

@app.route("/api/submolts")
def api_submolts():
    key = get_optional_api_key()
    log(f"SUBMOLTS auth={'yes' if key else 'no'}", "INFO")

    hdrs = auth_headers(key) if key else None
    result = api_request("submolts", headers=hdrs)
    submolts = get_submolts(result)
    if submolts:
        submolts.sort(key=lambda s: s.get("subscriber_count", 0), reverse=True)

    return jsonify({
        "success": not result.get("_error"),
        "submolts": submolts,
        "count": result.get("count", len(submolts)),
        "error": result.get("error"),
        "_stats": request_stats
    })

@app.route("/api/submolt/<name>/posts")
def api_submolt_posts(name):
    key = get_optional_api_key()
    log(f"SUBMOLT POSTS: {name} auth={'yes' if key else 'no'}", "INFO")

    hdrs = auth_headers(key) if key else None
    result = api_request("posts", {"submolt": name, "limit": INITIAL_LIMIT, "sort": "hot"}, headers=hdrs)
    posts = get_posts(result)

    return jsonify({
        "success": not result.get("_error"),
        "posts": posts,
        "error": result.get("error"),
        "_stats": request_stats
    })

# ============================================================================
# SINGLE POST
# ============================================================================
@app.route("/api/post/<post_id>")
def api_single_post(post_id):
    key = get_optional_api_key()
    log(f"POST: {post_id} auth={'yes' if key else 'no'}", "INFO")

    hdrs = auth_headers(key) if key else None
    result = api_request(f"posts/{post_id}", headers=hdrs)

    if result.get("_error"):
        return jsonify({"success": False, "error": result.get("error"), "_stats": request_stats})

    post = result.get("post", {})
    comments = result.get("comments", [])

    cache_agent_from_post_detail(result)
    
    # Scan comments with default keywords for single post view
    flagged_comments = scan_comments_for_keywords(comments)

    return jsonify({
        "success": True,
        "post": post,
        "comments": comments,
        "flagged_comments": flagged_comments,
        "_stats": request_stats
    })

# ============================================================================
# SEARCH (now just proxies, client does the real work)
# ============================================================================
@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    if not q:
        return jsonify({"success": False, "error": "No query"})

    key = get_optional_api_key()
    log(f"SEARCH: {q} auth={'yes' if key else 'no'}", "INFO")

    hdrs = auth_headers(key) if key else None
    result = api_request("search", {"q": q, "limit": 50}, headers=hdrs)
    posts = get_posts(result)

    return jsonify({
        "success": not result.get("_error"),
        "posts": posts,
        "error": result.get("error"),
        "_stats": request_stats
    })

# ============================================================================
# AGENT
# ============================================================================
@app.route("/api/agent/<name>")
def api_find_agent(name):
    key = get_optional_api_key()
    log(f"AGENT: {name} auth={'yes' if key else 'no'}", "INFO")

    hdrs = auth_headers(key) if key else None

    direct = api_request(f"agents/{name}", headers=hdrs)
    if not direct.get("_error"):
        agent = direct.get("agent") or direct
        if isinstance(agent, dict) and "owner" in agent:
            agent["owner"] = normalize_owner(agent.get("owner") or {})
        agent["post_count"] = agent.get("post_count", "?")
        return jsonify({"success": True, "agent": agent, "posts": [], "_stats": request_stats})

    name_lower = name.lower()
    cached_agent = agent_cache.get(name_lower)

    search_result = api_request("search", {"q": name, "limit": 30}, headers=hdrs)
    all_posts = get_posts(search_result)
    agent_posts = [p for p in all_posts if (p.get("author", {}).get("name", "") or "").lower() == name_lower]

    if agent_posts and not cached_agent:
        first_id = agent_posts[0].get("id")
        if first_id:
            detail = api_request(f"posts/{first_id}", headers=hdrs)
            if not detail.get("_error"):
                cache_agent_from_post_detail(detail)
                cached_agent = agent_cache.get(name_lower)

    if cached_agent or agent_posts:
        agent = cached_agent or {"name": name}
        agent["post_count"] = len(agent_posts)
        return jsonify({"success": True, "agent": agent, "posts": agent_posts[:15], "_stats": request_stats})

    return jsonify({"success": False, "error": f"Agent '{name}' not found", "_stats": request_stats})

# ============================================================================
# ME
# ============================================================================
@app.route("/api/me")
def api_me():
    api_key = (request.headers.get("X-API-Key") or "").strip()
    if not api_key:
        return jsonify({"success": False, "error": "API key required"})

    log("MY AGENT (with status check)", "INFO")

    status_check = api_request("agents/status", headers=auth_headers(api_key))
    status_info = {
        "status": status_check.get("status"),
        "agent_name": (status_check.get("agent") or {}).get("name") if isinstance(status_check.get("agent"), dict) else None,
        "error": status_check.get("error"),
        "inconsistent": False
    }

    pre = api_request("agents/me", headers=auth_headers(api_key))
    
    if not status_check.get("_error") and status_check.get("status") == "claimed" and pre.get("_error"):
        status_info["inconsistent"] = True
        status_info["me_error"] = pre.get("error")
    
    if pre.get("_error"):
        return jsonify({
            "success": False, 
            "error": pre.get("error"), 
            "status_check": status_info,
            "_stats": request_stats
        })

    agent = pre.get("agent") or pre
    owner = normalize_owner((agent.get("owner") or {}) if isinstance(agent, dict) else {})

    if isinstance(agent, dict):
        agent["owner"] = owner

    hint = None
    raw_handle = (agent.get("owner") or {}).get("xHandle") or (agent.get("owner") or {}).get("x_handle") or ""
    if not owner.get("x_handle") and not raw_handle:
        hint = "⚠️ UNCLAIMED: No X account linked. Go to moltbook.com and claim this agent by linking your X account."
    elif not owner.get("x_verified"):
        hint = f"⚠️ CLAIMED BUT NOT VERIFIED: Your agent is linked to X (@{raw_handle}) but x_verified=false. Go to moltbook.com and complete the VERIFICATION step (OAuth or tweet verification). Posts work, but COMMENTS require verification."

    posts = []
    if isinstance(agent, dict) and agent.get("name"):
        search = api_request("search", {"q": agent["name"], "limit": 20}, headers=auth_headers(api_key))
        all_posts = get_posts(search)
        posts = [p for p in all_posts if (p.get("author", {}).get("name", "") or "").lower() == agent["name"].lower()]

    out = {
        "success": True, 
        "agent": agent, 
        "posts": posts, 
        "status_check": status_info,
        "_stats": request_stats
    }
    if hint:
        out["hint"] = hint
    return jsonify(out)

# ============================================================================
# CREATE CONTENT
# ============================================================================
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    name = (data.get("name", "") or "").strip()
    desc = (data.get("description", "") or "").strip()

    log(f"REGISTER: {name}", "INFO")

    if not name:
        return jsonify({"success": False, "error": "Name required"})
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return jsonify({"success": False, "error": "Alphanumeric only"})

    result = api_request("agents/register", method="POST", data={"name": name, "description": desc})

    if not result.get("_error"):
        agent = result.get("agent") or result
        if isinstance(agent, dict) and agent.get("api_key"):
            return jsonify({
                "success": True, 
                "api_key": agent["api_key"],
                "claim_url": agent.get("claim_url"),
                "verification_code": agent.get("verification_code")
            })

    return jsonify({"success": False, "error": result.get("error", "Failed")})

@app.route("/api/post", methods=["POST"])
def api_create_post():
    data = request.get_json() or {}
    api_key = (request.headers.get("X-API-Key") or data.get("api_key") or "").strip()
    submolt = (data.get("submolt", "general") or "").strip()
    title = (data.get("title", "") or "").strip()
    content = (data.get("content", "") or "").strip()

    log(f"CREATE POST: {title[:40]}...", "INFO")

    if not api_key:
        return jsonify({"success": False, "error": "API key required"})
    if not title:
        return jsonify({"success": False, "error": "Title required"})

    status = api_request("agents/status", headers=auth_headers(api_key))
    pre = api_request("agents/me", headers=auth_headers(api_key))
    
    diagnostics = {
        "status_check": {"status": status.get("status"), "error": status.get("error")},
        "me_check": {"error": pre.get("error")}
    }
    
    if pre.get("_error"):
        return jsonify({
            "success": False, 
            "error": f"Auth failed: {pre.get('error')}", 
            "diagnostics": diagnostics, 
            "_stats": request_stats
        })

    result = api_request("posts", method="POST",
                        data={"submolt": submolt, "title": title, "content": content},
                        headers=auth_headers(api_key))

    if not result.get("_error"):
        post = result.get("post") or result
        return jsonify({"success": True, "post_id": post.get("id"), "_stats": request_stats})

    hint = None
    agent = (pre.get("agent") or pre) if isinstance(pre, dict) else {}
    owner = normalize_owner((agent.get("owner") or {}) if isinstance(agent, dict) else {})
    if result.get("status") in (401, 403) and (not owner.get("x_handle") or not owner.get("x_verified")):
        hint = "Your key is valid, but this agent may be unclaimed/unverified. Moltbook may restrict posting until verified."

    return jsonify({
        "success": False, 
        "error": result.get("error", "Failed"), 
        "hint": hint, 
        "diagnostics": diagnostics, 
        "_stats": request_stats
    })

@app.route("/api/comment", methods=["POST"])
def api_create_comment():
    data = request.get_json() or {}
    api_key = (request.headers.get("X-API-Key") or data.get("api_key") or "").strip()
    post_id = (data.get("post_id") or "").strip()
    content = (data.get("content") or "").strip()

    log(f"COMMENT on {post_id}", "INFO")

    if not api_key or not post_id or not content:
        return jsonify({"success": False, "error": "Missing fields", "_stats": request_stats})

    status_result = api_request("agents/status", headers=auth_headers(api_key))
    me_result = api_request("agents/me", headers=auth_headers(api_key))
    
    me_agent = me_result.get("agent") if isinstance(me_result, dict) else None
    if not me_result.get("_error") and not me_agent and isinstance(me_result, dict):
        me_agent = me_result

    owner_norm = normalize_owner((me_agent or {}).get("owner") if isinstance(me_agent, dict) else {})

    diagnostics = {
        "status_endpoint": {
            "ok": not status_result.get("_error"),
            "status": status_result.get("status"),
            "agent_name": (status_result.get("agent") or {}).get("name") if isinstance(status_result.get("agent"), dict) else None,
            "error": status_result.get("error"),
        },
        "me_endpoint": {
            "ok": not me_result.get("_error"),
            "agent_name": (me_agent or {}).get("name") if isinstance(me_agent, dict) else None,
            "error": me_result.get("error"),
            "owner": owner_norm,
        },
        "tries": []
    }

    endpoints = [
        f"posts/{post_id}/comments",
        f"posts/{post_id}/comment",
        "comments"
    ]
    payloads = [
        {"content": content},
        {"text": content},
        {"body": content},
        {"post_id": post_id, "content": content},
    ]
    header_styles = ["bearer", "x_only"]

    for ep in endpoints:
        for hs in header_styles:
            hdrs = auth_headers(api_key, hs)
            for payload in payloads:
                if ep.startswith("posts/") and "post_id" in payload:
                    continue

                result = api_request(ep, method="POST", data=payload, headers=hdrs)
                diagnostics["tries"].append({
                    "endpoint": f"POST /{ep}",
                    "header_style": hs,
                    "body_keys": list(payload.keys()),
                    "status": result.get("status"),
                    "error": result.get("error")
                })

                if not result.get("_error") and not result.get("_html"):
                    return jsonify({"success": True, "comment": result.get("comment") or result, "_stats": request_stats})

    hint = None
    statuses = [t.get("status") for t in diagnostics["tries"] if t.get("status") is not None]
    all_authy = statuses and all(s in (401, 403) for s in statuses)
    
    is_claimed = not status_result.get("_error") and status_result.get("status") == "claimed"
    is_verified = owner_norm.get("x_verified") == True
    
    raw_handle = ""
    if me_agent and isinstance(me_agent, dict):
        raw_owner = me_agent.get("owner", {}) or {}
        raw_handle = raw_owner.get("xHandle") or raw_owner.get("x_handle") or ""
    
    if is_claimed and not is_verified and all_authy:
        hint = (
            f"🔐 VERIFICATION REQUIRED: Your agent is CLAIMED (linked to @{raw_handle}) but NOT VERIFIED (x_verified=false). "
            "Moltbook allows posting without verification, but COMMENTS require the verification step. "
            "Go to moltbook.com → your agent profile → complete the verification process (usually OAuth or tweet verification)."
        )
    elif all_authy and not raw_handle:
        hint = (
            "⚠️ UNCLAIMED AGENT: No X account linked. Go to moltbook.com and claim this agent first, then verify it."
        )
    elif all_authy:
        hint = (
            "All comment attempts returned 401/403. The API may have additional permission requirements."
        )

    return jsonify({
        "success": False,
        "error": "Comment failed (see diagnostics)",
        "hint": hint,
        "diagnostics": diagnostics,
        "_stats": request_stats
    })

# ============================================================================
# FLAGGED - ENHANCED WITH CUSTOM CONFIG (POST method)
# ============================================================================
@app.route("/api/flagged", methods=["GET", "POST"])
def api_flagged():
    key = get_optional_api_key()
    
    # Get config from POST body or use defaults
    if request.method == "POST":
        config = request.get_json() or {}
        keywords = config.get("keywords", DEFAULT_CONCERNING_KEYWORDS)
        monitored_submolts = config.get("submolts", [])
        use_fuzzy = config.get("fuzzy", True)
        threshold = config.get("threshold", 0.75)
        deep_comments = config.get("deep_comments", True)
    else:
        keywords = DEFAULT_CONCERNING_KEYWORDS
        monitored_submolts = []
        use_fuzzy = True
        threshold = 0.75
        deep_comments = True
    
    log(f"FLAGGED: keywords={len(keywords)}, submolts={len(monitored_submolts)}, fuzzy={use_fuzzy}, threshold={threshold}", "INFO")

    hdrs = auth_headers(key) if key else None
    
    # PRIORITY: Fetch NEW posts first, then hot (reduced limits for speed)
    log("FLAGGED: Fetching new posts...", "INFO")
    new_result = api_request("posts", {"sort": "new", "limit": 40}, headers=hdrs)
    new_posts = get_posts(new_result)
    
    log("FLAGGED: Fetching hot posts...", "INFO")
    hot_result = api_request("posts", {"sort": "hot", "limit": 30}, headers=hdrs)
    hot_posts = get_posts(hot_result)
    
    # Also fetch from monitored submolts if specified (limit to 3 for speed)
    submolt_posts = []
    for sub in monitored_submolts[:3]:
        log(f"FLAGGED: Fetching submolt m/{sub}...", "INFO")
        sub_result = api_request("posts", {"submolt": sub, "limit": 20, "sort": "new"}, headers=hdrs)
        submolt_posts.extend(get_posts(sub_result))
    
    # Deduplicate by ID, prioritize new posts
    seen_ids = set()
    all_posts = []
    
    for p in new_posts:
        if p.get("id") not in seen_ids:
            p["_source"] = "new"
            all_posts.append(p)
            seen_ids.add(p.get("id"))
    
    for p in hot_posts:
        if p.get("id") not in seen_ids:
            p["_source"] = "hot"
            all_posts.append(p)
            seen_ids.add(p.get("id"))
    
    for p in submolt_posts:
        if p.get("id") not in seen_ids:
            sub_name = p.get("submolt", {}).get("name", "?") if isinstance(p.get("submolt"), dict) else p.get("submolt", "?")
            p["_source"] = f"m/{sub_name}"
            all_posts.append(p)
            seen_ids.add(p.get("id"))

    log(f"FLAGGED: Scanning {len(all_posts)} posts for keywords...", "INFO")
    
    flagged = []
    posts_needing_comment_scan = []
    total_comments_scanned = 0
    
    # PHASE 1: Quick scan of titles/content (no API calls)
    for p in all_posts:
        text = f"{p.get('title', '')} {p.get('content', '')}".lower()
        title_kw = check_text_for_keywords_fuzzy(text, keywords, use_fuzzy, threshold)
        
        if title_kw:
            exact_match = title_kw.lower() in text.lower()
            p["_fuzzy"] = not exact_match
            p["_kw"] = title_kw
            flagged.append(p)
        elif deep_comments and p.get("comment_count", 0) > 0:
            # Queue for comment scanning (only if title didn't flag)
            posts_needing_comment_scan.append(p)
    
    # PHASE 2: Deep comment scan (LIMITED to avoid hanging)
    # Only scan top 15 posts by comment count to avoid API overload
    if deep_comments and posts_needing_comment_scan:
        posts_needing_comment_scan.sort(key=lambda x: x.get("comment_count", 0), reverse=True)
        to_scan = posts_needing_comment_scan[:15]  # LIMIT to 15 posts max
        
        log(f"FLAGGED: Deep scanning comments on {len(to_scan)} posts...", "INFO")
        
        for i, p in enumerate(to_scan):
            log(f"FLAGGED: Comment scan {i+1}/{len(to_scan)}...", "DEBUG")
            detail = api_request(f"posts/{p.get('id')}", headers=hdrs)
            if not detail.get("_error"):
                comments = detail.get("comments", [])
                flagged_comments = scan_comments_for_keywords_fuzzy(comments, keywords, use_fuzzy, threshold)
                total_comments_scanned += len(comments)
                if flagged_comments:
                    p["_comment_kw"] = flagged_comments[0]["keyword"]
                    if p not in flagged:
                        flagged.append(p)

    log(f"FLAGGED: Complete. Found {len(flagged)} flagged posts.", "SUCCESS")

    # Sort by source priority (new first) then karma
    def sort_key(p):
        source_priority = 0 if p.get("_source") == "new" else 1
        karma = (p.get("upvotes", 0) - p.get("downvotes", 0))
        return (source_priority, -karma)
    
    flagged.sort(key=sort_key)

    return jsonify({
        "success": True, 
        "posts": flagged[:50], 
        "all_posts": all_posts,  # Return all for client-side search pool
        "scanned_posts": len(all_posts),
        "scanned_comments": total_comments_scanned,
        "comment_posts_scanned": min(15, len(posts_needing_comment_scan)) if deep_comments else 0,
        "_stats": request_stats
    })

# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🦞 MOLTBOOK EXPLORER v7.3.2 — PERSISTENT CONFIG + FUZZY MATCH")
    print("=" * 60)
    print(f"\n📡 API: {BASE_URL}")
    print("🌐 Open: http://localhost:5000")
    print("\nv7.3.2 fixes:")
    print("  • Deep scan now limits comment fetches (max 15 posts)")
    print("  • Faster scanning with progress logging")
    print("  • Reduced API calls to prevent hangs")
    print("\nFeatures:")
    print("  • Persistent keyword management (localStorage)")
    print("  • Fuzzy grep matching with adjustable threshold")
    print("  • Priority scanning of NEW posts")
    print("  • Configurable submolt monitoring list")
    print("  • Client-side search (filters loaded posts)")
    print("\nPress Ctrl+C to stop\n")
    print("=" * 60 + "\n")

    app.config["DEBUG"] = False
    app.config["ENV"] = "production"

    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True, use_reloader=False)
