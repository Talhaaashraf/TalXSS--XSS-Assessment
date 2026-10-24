"""Report rendering for TalXSS scan results (JSON + standalone HTML)."""

from __future__ import annotations

import json
import html
import time

from .scanner import ScanResult

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2)


def pdf_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def to_pdf(html_str: str, out_path: str) -> bool:
    """Render the HTML report to a PDF using headless Chromium (Playwright).

    Returns True on success. If Playwright/Chromium isn't available, returns
    False so the caller can fall back to 'print the HTML from your browser'.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_content(html_str, wait_until="load")
            page.pdf(path=out_path, format="A4", print_background=True,
                     margin={"top": "14mm", "bottom": "14mm", "left": "10mm", "right": "10mm"})
            browser.close()
        return True
    except Exception:
        return False


def to_html(result: ScanResult, tool_version: str = "1.0.0",
            branding: dict | None = None) -> str:
    d = result.as_dict()
    b = branding or {}
    findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    rows = []
    for f in findings:
        # Fall back to name/note so recon rows (no payload/evidence) aren't blank.
        what = f.payload or getattr(f, "payload_name", "") or "—"
        detail = f.evidence or f.note or "—"
        poc = getattr(f, "poc", "") or ""
        if poc.startswith(("http://", "https://")):
            poc_cell = f'<a href="{html.escape(poc)}" target="_blank" rel="noopener">{html.escape(poc)}</a>'
        elif poc:
            poc_cell = html.escape(poc)
        else:
            poc_cell = "—"
        rows.append(f"""
        <tr class="sev-{html.escape(f.severity)}">
          <td><span class="badge">{html.escape(f.severity.upper())}</span></td>
          <td>{html.escape(getattr(f, 'attack_type', ''))}</td>
          <td>{html.escape(f.method)}</td>
          <td class="mono">{html.escape(f.url)}</td>
          <td class="mono">{html.escape(f.parameter)}</td>
          <td class="mono small">{html.escape(what)}</td>
          <td class="mono small">{html.escape(detail)}</td>
          <td class="mono small poc">{poc_cell}</td>
        </tr>""")
    body_rows = "".join(rows) or (
        '<tr><td colspan="8">No XSS confirmed in the tested scope (target likely encodes output).</td></tr>'
    )
    generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    recon = d.get("recon") or {}
    waf = d.get("waf") or {}
    if waf.get("present"):
        waf_line = (f"<b>{html.escape(str(waf.get('name', 'unknown')))}</b> "
                    f"— confidence {html.escape(str(waf.get('confidence', 'none')))}, "
                    f"actively blocking: {waf.get('blocking', False)}")
    else:
        waf_line = "<b>None fingerprinted</b> on the baseline response"
    recon_items = "".join(
        f"<li><b>{html.escape(str(k))}:</b> {html.escape(str(v))}</li>"
        for k, v in recon.items()
    ) or "<li>No server/technology headers disclosed.</li>"
    recon_html = (f'<h2>Recon &amp; WAF</h2><div class="recon">'
                  f'<div class="waf">🛡️ Firewall / WAF: {waf_line}</div>'
                  f'<ul>{recon_items}</ul></div>')

    # Honest top-of-report banner: unreachable vs. clean vs. findings.
    reachable = d.get("target_reachable", True)
    ok = d.get("ok_responses", 0)
    if not reachable:
        banner = ('<div class="banner bad">✗ TARGET UNREACHABLE — every request failed '
                  '(connection refused / timeout / DNS). Nothing was actually tested; '
                  'this report is empty because no attack reached the target, not because '
                  'the target is secure. Check the URL, network/VPN, and that the host is up.</div>')
    elif not findings:
        banner = (f'<div class="banner ok">✓ Target reached ({ok} responses) but no XSS was '
                  'confirmed — reflected input is encoded/blocked on the tested surface. '
                  'This is a real, correct result (the target is defending itself).</div>')
    else:
        banner = (f'<div class="banner hit">● {len(findings)} finding(s) — target reached with '
                  f'{ok} responses. Use the PoC column to reproduce each one.</div>')

    # Branding header (assessor / organisation / engagement) for client delivery.
    org = html.escape(str(b.get("org", "") or ""))
    assessor = html.escape(str(b.get("assessor", "") or ""))
    engagement = html.escape(str(b.get("engagement", "") or ""))
    logo = b.get("logo", "")  # a data: URI or URL, caller-supplied
    brand_bits = []
    if org:
        brand_bits.append(f"<b>{org}</b>")
    if engagement:
        brand_bits.append(f"Engagement: {engagement}")
    if assessor:
        brand_bits.append(f"Assessor: {assessor}")
    logo_html = (f'<img src="{html.escape(logo)}" alt="logo" class="logo">' if logo else "")
    brand_html = (f'<div class="brand">{logo_html}<div>{" · ".join(brand_bits)}</div></div>'
                  if (brand_bits or logo_html) else "")

    sev_summary = (f'<div class="sevsum">'
                   f'<span class="chip high">High: {sev_counts["high"]}</span>'
                   f'<span class="chip medium">Medium: {sev_counts["medium"]}</span>'
                   f'<span class="chip low">Low: {sev_counts["low"]}</span></div>')

    remediation_html = (
        '<h2>Remediation</h2><div class="recon"><ul>'
        '<li><b>Context-aware output encoding</b> at every sink (HTML body, attribute, '
        'JS string, URL) — prefer the framework\'s auto-escaping and never build markup '
        'by string concatenation of untrusted input.</li>'
        '<li><b>Strict Content-Security-Policy</b> (e.g. <code>default-src \'self\'</code>, '
        'no <code>unsafe-inline</code>/<code>unsafe-eval</code>) as defence-in-depth.</li>'
        '<li><b>Validate &amp; normalise input</b> server-side; reject unexpected markup.</li>'
        '<li><b>Cookie flags</b>: set <code>HttpOnly</code>, <code>Secure</code>, '
        '<code>SameSite</code> to limit the impact of any XSS.</li>'
        '<li>For <b>DOM XSS</b>, use safe sinks (<code>textContent</code>, not '
        '<code>innerHTML</code>) and libraries like DOMPurify for rich content.</li>'
        '</ul></div>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>TalXSS Report — {html.escape(d['config_url'])}</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin:0 0 .25rem}} .sub{{color:#666}}
 .cards{{display:flex;gap:1rem;margin:1.5rem 0;flex-wrap:wrap}}
 .card{{background:#fff;border:1px solid #e3e3e3;border-radius:10px;padding:1rem 1.25rem;min-width:120px}}
 .card b{{font-size:1.6rem;display:block}}
 table{{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e3e3e3;border-radius:10px;overflow:hidden}}
 th,td{{padding:.6rem .7rem;text-align:left;border-bottom:1px solid #eee;vertical-align:top}}
 th{{background:#f2f2f2;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}}
 .mono{{font-family:ui-monospace,Consolas,monospace;word-break:break-all}} .small{{font-size:.78rem}}
 .badge{{padding:.15rem .5rem;border-radius:999px;color:#fff;font-size:.72rem;font-weight:700}}
 .sev-high .badge{{background:#c0392b}} .sev-medium .badge{{background:#d35400}} .sev-low .badge{{background:#7f8c8d}}
 .recon{{background:#fff;border:1px solid #e3e3e3;border-radius:10px;padding:1rem 1.25rem;margin:.5rem 0 1.5rem}}
 .recon .waf{{font-size:1.05rem;margin-bottom:.5rem}} .recon ul{{margin:.3rem 0 0;padding-left:1.2rem;color:#444}}
 td.poc a{{color:#1f6feb}} td.poc{{max-width:340px}}
 .banner{{padding:.9rem 1.1rem;border-radius:10px;margin:1rem 0;font-weight:600}}
 .banner.bad{{background:#fdecea;border:1px solid #c0392b;color:#8a1f14}}
 .banner.ok{{background:#eafaf1;border:1px solid #2e9e5b;color:#1d6b3c}}
 .banner.hit{{background:#fff4e5;border:1px solid #d35400;color:#8a4300}}
 .brand{{display:flex;align-items:center;gap:1rem;border-bottom:2px solid #e3e3e3;padding-bottom:.8rem;margin-bottom:1rem;color:#333}}
 .brand .logo{{max-height:48px;max-width:160px}}
 .sevsum{{display:flex;gap:.6rem;margin:.4rem 0 1rem}}
 .chip{{padding:.25rem .7rem;border-radius:999px;color:#fff;font-weight:700;font-size:.8rem}}
 .chip.high{{background:#c0392b}} .chip.medium{{background:#d35400}} .chip.low{{background:#7f8c8d}}
 code{{background:#f2f2f2;padding:.05rem .3rem;border-radius:4px;font-size:.85em}}
 footer{{margin-top:2rem;color:#888;font-size:.8rem}}
</style></head><body>
{brand_html}
<h1>TalXSS Assessment Report</h1>
<div class="sub">Target: <b>{html.escape(d['config_url'])}</b> · Generated {generated} · v{tool_version}</div>
{banner}
{sev_summary}
<div class="cards">
  <div class="card"><b>{len(findings)}</b>Confirmed findings</div>
  <div class="card"><b>{d['pages_crawled']}</b>Pages crawled</div>
  <div class="card"><b>{d['params_tested']}</b>Params tested</div>
  <div class="card"><b>{len(d['reflections'])}</b>Reflections</div>
  <div class="card"><b>{d['requests_made']}</b>Requests</div>
  <div class="card"><b>{d['duration']}s</b>Duration</div>
</div>
{recon_html}
<h2>Findings</h2>
<table>
 <tr><th>Severity</th><th>Type</th><th>Method</th><th>URL</th><th>Param</th><th>Payload / What</th><th>Evidence / Detail</th><th>PoC — reproduce</th></tr>
 {body_rows}
</table>
{remediation_html}
<footer>Generated by TalXSS — authorized security assessment only. Findings indicate attacker-controlled
input reaching an HTML/JS sink unescaped. Remediate via context-aware output encoding and a strict
Content-Security-Policy.</footer>
</body></html>"""
