"""TalXSS command-line runner.

Example:
  python -m talxss.cli "http://127.0.0.1:8000/search?q=test" \
      --scope 127.0.0.1 --authorize --out report.html

Refuses to run without --authorize. Keep scope tight.
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

from . import __version__
from .scanner import Scanner, ScanConfig, AuthorizationError, ScopeError
from .report import to_html, to_json
from .payloads import ATTACK_TYPES, available_wordlists
from .store import DEFAULT_DB


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="talxss", description="Authorized XSS assessment tool")
    ap.add_argument("target", help="Start URL (http[s]://...)")
    ap.add_argument("--scope", nargs="*", default=None,
                    help="Allowed hosts. Defaults to the target host.")
    ap.add_argument("--authorize", action="store_true",
                    help="Confirm you are authorized to test the target. Required.")
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--no-crawl", action="store_true")
    ap.add_argument("--no-forms", action="store_true")
    ap.add_argument("--insecure", action="store_true", help="Do not verify TLS certs.")
    ap.add_argument("--out", help="Write an HTML (.html) or JSON (.json) report.")
    ap.add_argument("--attack-types", default=None,
                    help=f"Comma list to run manually. Choices: {','.join(ATTACK_TYPES)}. "
                         "Default = all.")
    ap.add_argument("--wordlists", default=None,
                    help="Comma list of .txt files in payload_lists/ to fire. Default = all.")
    ap.add_argument("--list-wordlists", action="store_true",
                    help="Show available payload lists and exit.")
    ap.add_argument("--max-wordlist", type=int, default=250,
                    help="Cap raw wordlist payloads fired per injection point.")
    ap.add_argument("--no-store", action="store_true", help="Do not persist this scan.")
    ap.add_argument("--db", default=str(DEFAULT_DB), help="SQLite store path.")
    ap.add_argument("--version", action="version", version=f"TalXSS {__version__}")
    args = ap.parse_args(argv)

    if args.list_wordlists:
        for w in available_wordlists():
            print(w)
        return 0

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    scope = args.scope or [urlparse(target).hostname or ""]

    attack_types = None
    if args.attack_types:
        attack_types = [t.strip() for t in args.attack_types.split(",") if t.strip()]
        bad = [t for t in attack_types if t not in ATTACK_TYPES]
        if bad:
            print(f"Unknown attack type(s): {bad}. Choices: {ATTACK_TYPES}", file=sys.stderr)
            return 2
    wordlists = None
    if args.wordlists:
        wordlists = [w.strip() for w in args.wordlists.split(",") if w.strip()]

    cfg = ScanConfig(
        start_url=target, scope=[s for s in scope if s], authorized=args.authorize,
        max_pages=args.max_pages, delay=args.delay,
        crawl=not args.no_crawl, include_forms=not args.no_forms,
        verify_tls=not args.insecure,
        attack_types=attack_types, wordlist_files=wordlists,
        max_wordlist=args.max_wordlist,
        store_path=None if args.no_store else args.db,
    )

    try:
        result = Scanner(cfg, logger=lambda m: print(m, flush=True)).run()
    except AuthorizationError as e:
        print(f"\n[REFUSED] {e}\nPass --authorize only for targets you may legally test.", file=sys.stderr)
        return 2
    except ScopeError as e:
        print(f"\n[REFUSED] {e}", file=sys.stderr)
        return 2

    print(f"\n=== {len(result.findings)} finding(s) ===")
    for f in result.findings:
        print(f"  [{f.severity.upper()}] [{f.attack_type}] {f.method} {f.url} "
              f"param={f.parameter} ({f.payload_name})")

    if args.out:
        if args.out.endswith(".json"):
            data = to_json(result)
        else:
            data = to_html(result, __version__)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(data)
        print(f"\nReport written to {args.out}")

    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
