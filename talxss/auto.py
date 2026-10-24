"""TalXSS Auto — one-command black-box XSS assessment.

Give it a target; it does everything else:
    python -m talxss.auto https://authorized-target.example --authorize

Pipeline (all automatic): recon → WAF detection → crawl → reflected / stored /
DOM / header / mutation XSS → headless-browser execution verification → writes an
HTML + JSON report. Scope defaults to the target's host. Authorized targets only
— the --authorize confirmation is mandatory and the host-scope guard still applies.
"""

from __future__ import annotations

import sys
import time
import argparse
from urllib.parse import urlparse

from . import __version__
from .scanner import Scanner, ScanConfig, AuthorizationError, ScopeError
from .report import to_html, to_json
from . import verify as _verify


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="talxss-auto",
        description="One-command black-box XSS assessment (recon→WAF→crawl→attack→verify→report).")
    ap.add_argument("target", help="Target URL (just give this).")
    ap.add_argument("--authorize", action="store_true",
                    help="Confirm you are authorized to test this target. REQUIRED.")
    ap.add_argument("--scope", nargs="*", default=None,
                    help="Override in-scope hosts (default: the target's host).")
    ap.add_argument("--delay", type=float, default=0.2, help="Seconds between requests.")
    ap.add_argument("--max-pages", type=int, default=60, help="Crawl cap.")
    ap.add_argument("--confirm", type=int, default=3, help="Re-verify each finding N times (3..6).")
    ap.add_argument("--no-verify", action="store_true", help="Skip headless-browser verification.")
    ap.add_argument("--out", default=None, help="Report path base (default: auto-named).")
    ap.add_argument("--insecure", action="store_true", help="Do not verify TLS certs.")
    args = ap.parse_args(argv)

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    host = urlparse(target).hostname or ""
    scope = args.scope or [host]
    scope = [s for s in scope if s]

    if not args.authorize:
        print("REFUSED: you must confirm authorization to test this target.", file=sys.stderr)
        print(f"  Run:  python -m talxss.auto {target} --authorize", file=sys.stderr)
        print("  Only scan systems you own or have explicit written permission to test.",
              file=sys.stderr)
        return 2
    if not scope:
        print("REFUSED: could not derive a scope host from the target.", file=sys.stderr)
        return 2

    use_verify = (not args.no_verify) and _verify.available()
    verify_note = "on (headless browser)" if use_verify else (
        "off — Playwright not installed; run: pip install playwright && python -m playwright install chromium"
        if not args.no_verify else "off (--no-verify)")

    print(f"╔═ TalXSS Auto v{__version__} — black-box assessment")
    print(f"║  target : {target}")
    print(f"║  scope  : {', '.join(scope)}")
    print(f"║  verify : {verify_note}")
    print(f"║  phases : recon → WAF → crawl → reflected/stored/DOM/header/mXSS → verify → report")
    print("╚" + "═" * 60 + "\n")

    cfg = ScanConfig(
        start_url=target, scope=scope, authorized=True,
        delay=args.delay, max_pages=args.max_pages,
        crawl=True, include_forms=True,
        attack_types=None,               # everything
        verify=use_verify, verbose=True,
        waf_check=True, recon=True, header_xss=True,
        multi_payload=True, confirm_repeat=args.confirm,
        verify_tls=not args.insecure,
    )

    try:
        result = Scanner(cfg, logger=lambda m: print(m, flush=True)).run()
    except (AuthorizationError, ScopeError) as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2

    base = args.out or f"talxss-report-{host or 'target'}-{time.strftime('%Y%m%d-%H%M%S')}"
    html_path, json_path = base + ".html", base + ".json"
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(to_html(result, __version__))
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(to_json(result))

    print("\n" + "═" * 62)
    if not result.target_reachable:
        print("RESULT: ✗ TARGET UNREACHABLE — every request failed, nothing was tested.")
        print("        Check the URL, your network/VPN, and that the host is up, then retry.")
    else:
        confirmed = [f for f in result.findings if "CONFIRMED" in (f.note or "")]
        print(f"RESULT: {len(result.findings)} finding(s) across {result.pages_crawled} page(s), "
              f"{result.ok_responses} requests reached the target.")
        if confirmed:
            print(f"        ✓ {len(confirmed)} browser-CONFIRMED (JavaScript actually executed).")
        if not result.findings:
            print("        No XSS found — the target encodes/defends its output on the tested")
            print("        surface. That is a real, correct result, not a tool failure.")
        else:
            print("        Open the report and use the PoC column to reproduce each finding.")
    print(f"Report (HTML): {html_path}")
    print(f"Report (JSON): {json_path}")
    print("═" * 62)
    return 0 if result.target_reachable else 3


if __name__ == "__main__":
    raise SystemExit(main())
