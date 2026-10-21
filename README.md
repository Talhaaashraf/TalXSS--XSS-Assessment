# 🩸 TalXSS — The Father of XSS Assessment

**TalXSS** is a professional **VAPT tool for finding Cross-Site Scripting** (OWASP Top 10 —
A03:2021 Injection) in web applications. It combines a crawler, a context-aware detection
engine, manually selectable attack types, your own curated payload wordlists, stored-XSS
detection, persistent scan history, and HTML/JSON reporting — behind both a **web control
panel** (with a target bar) and a **command-line runner**.

> ## ⚠️ Authorized use only
> Scan only systems **you own** or have **explicit written authorization** to test — a signed
> penetration-test engagement, an in-scope bug-bounty program, or a lab you control.
> Unauthorized scanning is illegal in most jurisdictions and can cause real harm. TalXSS
> **refuses to run** until you confirm authorization and it **enforces the host scope** you
> declare. Payloads are benign proof-of-concept markers — the cookie category *demonstrates*
> that `document.cookie` is reachable (the impact a report must prove) but does **not**
> exfiltrate data anywhere.

## Features
- 🎯 **Target bar** web UI + CLI
- 🕷️ **Crawler** — same-host pages, URL parameters, GET/POST forms
- 🧠 **Context-aware engine** — classifies reflection (HTML / attribute / inline-JS / URL) and fires only payloads that fit, with low-false-positive confirmation (unescaped breakout required)
- 🧩 **Manual attack-type selection** — `reflected`, `stored`, `cookie`, `dom`, `polyglot`, `waf-bypass`, `wordlist`
- 📚 **Your wordlists** — drop `.txt` payload files in [`talxss/payload_lists/`](talxss/payload_lists/) and fire them as a live attack source
- 🗄️ **Stored-XSS detection** — submits persistence payloads, then re-crawls to catch them resurfacing on other pages
- 💾 **Persistent history** — every scan + all findings saved to `talxss.db` (SQLite)
- 📄 **Reports** — downloadable HTML and JSON

## Install
```bash
pip install -r requirements.txt
```

## Web UI (target bar)
```bash
python -m talxss.webapp      # http://127.0.0.1:5000  (localhost only)
```
Paste a target, set in-scope host(s), pick attack types + wordlists, tick authorization, Start
Scan. Watch live findings/log, download the report, and review past scans in the history panel.

## Command line
```bash
# Full assessment (all attack types), saved to history, HTML report:
python -m talxss.cli "https://authorized-site.example/?q=test" \
    --scope authorized-site.example --authorize --out report.html

# Manual: only stored + cookie attacks
python -m talxss.cli "https://authorized-site.example/" \
    --scope authorized-site.example --authorize --attack-types stored,cookie

# Use your own wordlists as the attack source
python -m talxss.cli "https://authorized-site.example/?q=x" \
    --scope authorized-site.example --authorize \
    --attack-types wordlist --wordlists All-xss-payloads.txt --max-wordlist 100

python -m talxss.cli x --list-wordlists   # show available lists
```

| Flag | Meaning |
|------|---------|
| `--scope H [H...]` | Allowed hosts (suffix match). Defaults to target host. |
| `--authorize` | Confirm you may legally test the target. **Required.** |
| `--attack-types a,b` | Manually choose attack classes. Default = all. |
| `--wordlists f,g` | `.txt` files in `payload_lists/` to fire. Default = all. |
| `--max-wordlist N` | Cap raw payloads fired per injection point (politeness). |
| `--max-pages N` · `--delay S` | Crawl cap · delay between requests. |
| `--no-crawl` · `--no-forms` · `--insecure` | Narrow the scan / skip forms / skip TLS verify. |
| `--out FILE` | Write `.html` or `.json` report. |
| `--no-store` · `--db PATH` | Don't persist / choose the SQLite store. |

## How it works
1. **Scope guard** — refuses any URL outside your authorized host allow-list.
2. **Crawl** — same-host links, collecting URL parameters and HTML forms.
3. **Probe** — injects a unique canary to learn *if and where* input reflects.
4. **Context detection** — HTML body, quoted attribute, inline `<script>`, or URL.
5. **Targeted payloads** — only the selected attack types for that context, plus your wordlists.
6. **Confirm** — a finding requires the breakout markup to appear **unescaped** (properly encoded reflections are not reported).
7. **Stored pass** — re-crawls pages to catch submitted payloads resurfacing elsewhere.
8. **Persist** — scan + findings written to `talxss.db`.

## Payload lists
The curated `.txt` vectors live in [`talxss/payload_lists/`](talxss/payload_lists/)
(master list, auto-execution, WAF-bypass/obfuscation, framework-specific, etc.). Add your own
`.txt` files there and they appear automatically in the UI and `--list-wordlists`.

## Remediation (put this in your report)
- **Context-aware output encoding** (HTML/attr/JS/URL) at every sink.
- Strict **Content-Security-Policy** (`default-src 'self'`; avoid `unsafe-inline`).
- Framework auto-escaping; treat all input as untrusted.
- `HttpOnly`/`Secure`/`SameSite` cookies to blunt impact.

## Limits
Detects server-reflected and stored XSS via response analysis. It does not execute JavaScript,
so purely client-side DOM XSS (JS sink with no server reflection) needs a headless-browser
verification pass — a clean next module. Rate-limited and single-threaded by design.

## Layout
```
talxss/
  scanner.py            crawl + inject + context-aware + stored engine
  payloads.py           canary tokens, context/attack-type payloads, wordlist loader
  store.py              SQLite scan + findings history
  report.py             HTML / JSON reports
  webapp.py             Flask control panel (localhost)
  cli.py                command-line runner
  templates/index.html  the target-bar UI
  payload_lists/        your curated .txt XSS vectors (attack source)
```

*For educational and authorized security-testing purposes only.*
