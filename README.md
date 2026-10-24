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
- 🛡️ **WAF/firewall detection first** — fingerprints Cloudflare/Akamai/AWS/Imperva/Sucuri/F5/ModSecurity etc. from headers, cookies, and one benign behavioural probe; reports it and **slows down** if blocking is seen (detect & report, never evade)
- 🔎 **Recon** — server/tech fingerprint + passive **security-header** analysis (missing/weak CSP, HSTS, X-Frame-Options, cookie flags…)
- 🧪 **All XSS classes** — reflected, stored, DOM (via `--verify`), **HTTP-header XSS** (`User-Agent`/`Referer`/`X-Forwarded-For`/`X-Forwarded-Host`), and **mutation XSS (mXSS)** probes
- 🎚️ **Broad context coverage** (PayloadsAllTheThings-informed) — HTML body, HTML5 event tags (autofocus/onfocus, ontoggle…), double/single-quoted attributes, inline `<script>`, SVG (`onload`/`<script>`/`animate`), `data:`/`vbscript:` URI wrappers, Markdown links, CSS `<style>` breakout, and XHTML-namespace script. Execution verification now reports the **origin** (`document.domain`) the payload fired in
- 🕷️ **Crawler** — same-host pages, URL parameters, GET/POST forms
- 🧠 **Reflection analysis** — probes exactly which characters survive unescaped at each point, *explains* why a point is or isn't exploitable, and **prunes payloads that cannot possibly work** (no more blasting 1000 useless vectors)
- 🎭 **Context-aware engine** — classifies reflection (HTML / attribute / inline-JS / URL) and fires only payloads that fit, with low-false-positive confirmation (unescaped breakout required)
- 🌐 **Headless-browser verification** (`--verify`) — loads the injected page in real Chromium and **confirms the JavaScript actually executed**; this also catches **DOM-based XSS** that never appears in the server HTML
- 🔁 **Thorough confirmation** — fires many payloads per point (records several findings), **re-verifies each 3–6×** so flukes aren't reported, and on a **WAF block retries obfuscated variants** to show which defeat the firewall (authorized WAF-coverage testing — reported, not stealthy evasion)
- 🧩 **Manual attack-type selection** — `reflected`, `stored`, `cookie`, `dom`, `polyglot`, `waf-bypass`, `wordlist`
- 📚 **Your wordlists** — drop `.txt` payload files in [`talxss/payload_lists/`](talxss/payload_lists/) and fire them as a live attack source
- 🗄️ **Stored-XSS detection** — submits persistence payloads, then re-crawls to catch them resurfacing on other pages
- 📣 **Verbose live log** — watch every probe/payload fire in real time (`-v` / UI toggle)
- 💾 **Persistent history** — every scan + all findings saved to `talxss.db` (SQLite)
- 📄 **Reports** — downloadable HTML and JSON

### Why "nothing happened" is sometimes the right answer
If a target properly **encodes its output**, XSS is *not* possible there — and a tool that still cried "vulnerable!" would be lying. TalXSS tells you *why*: e.g. `encoded: < > " '` means tag and attribute breakout are both blocked, so it skips those payloads instead of wasting requests. Real findings come from points where the breakout characters survive **and** (with `--verify`) the JavaScript is seen to run.

## Install
```bash
pip install -r requirements.txt
# optional but recommended for REAL (browser-confirmed) results:
pip install playwright && python -m playwright install chromium
```

## Easiest: one-command black-box scan
Give it only a target — it auto-runs recon → WAF detection → crawl → reflected/stored/
DOM/header/mXSS → **headless-browser execution verification** → and writes an HTML + JSON
report with a ready-to-run PoC per finding:
```bash
python -m talxss.auto https://authorized-target.example --authorize
```
Scope defaults to the target's host; `--authorize` is mandatory (authorized targets only).
If the target can't be reached, the report says so plainly — it never fakes a clean
"0 findings". Add `--no-verify` to skip the browser step, `--confirm 6` for max re-verification.

**For client engagements** (faster scan + branded, client-ready PDF):
```bash
python -m talxss.auto https://authorized-target.example --authorize \
    --concurrency 8 --pdf \
    --org "Your Company" --assessor "Your Name" --engagement "Q4 Web VAPT"
```
`--concurrency N` runs N injection points in parallel; `--pdf` renders a PDF (needs
Playwright); `--org/--assessor/--engagement/--logo` brand the report header. The report
includes a severity summary and a remediation section. In the web UI, **⚡ Full Auto Scan**
runs the same pipeline in parallel with one click.

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
| `-v`, `--verbose` | Log every probe and payload as it is fired. |
| `--verify` | Confirm execution in headless Chromium (needs Playwright); proves JS runs and catches DOM XSS. |
| `--no-waf` | Skip WAF/firewall detection (on by default, runs first). |
| `--no-recon` | Skip stack fingerprint + security-header analysis. |
| `--no-header-xss` | Skip XSS testing via request headers (UA/Referer/XFF). |
| `--confirm N` | Re-verify each finding N times (clamped 3–6). Default 3. |
| `--single` | Stop at the first confirmed finding per point (default: multiple). |
| `--max-per-point N` | Cap distinct confirmed findings per point (default 6). |
| `--no-waf-bypass` | Don't retry obfuscated variants when the WAF blocks a payload. |

## How it works (black-box pentest flow)
1. **Scope guard** — refuses any URL outside your authorized host allow-list.
2. **Recon + WAF first** — fingerprint the stack, analyse security headers, and detect/fingerprint the firewall before any attack; if it actively blocks a benign probe, throttle.
3. **Crawl** — same-host links, collecting URL parameters and HTML forms.
4. **Probe + reflection analysis** — a canary learns *if, where, and with which characters* input reflects; payloads that can't work are pruned.
5. **Context detection** — HTML body, quoted attribute, inline `<script>`, or URL.
6. **Targeted payloads** — only the selected attack types for that context, plus your wordlists.
7. **Confirm** — a finding requires the breakout markup to appear **unescaped** (properly encoded reflections are not reported).
8. **Header XSS** — repeat the test through `User-Agent`/`Referer`/`X-Forwarded-*` headers.
9. **Stored pass** — re-crawls pages to catch submitted payloads resurfacing elsewhere.
10. **Verify** (`--verify`) — headless Chromium confirms JS execution and catches DOM XSS.
11. **Persist** — scan + findings written to `talxss.db`.

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
Server-reflected and stored XSS are detected via response analysis (fast, no browser).
**DOM-based XSS and execution proof require `--verify`** (headless Chromium) — without it, DOM
sinks that never touch the server HTML are invisible, as they are to any reflection-only tool.
DOM XSS driven purely by the URL *fragment* (`#...`) is only covered for parameters the crawler
discovers. Rate-limited and single-threaded by design — an assessment tool, not a flood.

## Layout
```
talxss/
  scanner.py            recon→crawl→inject→context-aware→stored→verify engine
  recon.py              WAF/firewall detection + fingerprint + security headers
  analyzer.py           reflection character-survival analysis + payload pruning
  verify.py             headless-browser execution verification (Playwright)
  payloads.py           canary tokens, context/attack-type payloads, wordlist loader
  store.py              SQLite scan + findings history
  report.py             HTML / JSON reports
  webapp.py             Flask control panel (localhost)
  cli.py                command-line runner
  templates/index.html  the target-bar UI
  payload_lists/        your curated .txt XSS vectors (attack source)
```

*For educational and authorized security-testing purposes only.*
