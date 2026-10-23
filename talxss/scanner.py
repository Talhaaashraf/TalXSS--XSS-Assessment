"""TalXSS scanning engine.

Pipeline per target:
  1. Scope check  -> refuse anything outside the authorized host allow-list.
  2. Crawl        -> same-host pages, collecting URL parameters and HTML forms.
  3. Probe        -> inject a unique canary to learn IF and WHERE input reflects.
  4. Context test -> fire only payloads that make sense for that context.
  5. Confirm      -> a finding requires the payload's breakout markup to appear
                     UNESCAPED in the response (low false-positive detection).

The engine is intentionally polite: single-threaded with a configurable delay,
a crawl cap, and an identifying User-Agent, so it behaves like an authorized
assessment tool rather than a flood.
"""

from __future__ import annotations

import time
import html
import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin, urlencode, parse_qsl
from collections import deque
from typing import Callable, Iterable

import requests
from bs4 import BeautifulSoup

from .payloads import (new_canary, probe_payload, library_for_context,
                       stored_payloads, load_wordlist_payloads, exec_payloads, Payload)
from . import analyzer
from . import recon as _recon
from . import verify as _verify

DEFAULT_UA = "TalXSS/1.0 (+authorized-security-assessment)"


# --------------------------------------------------------------------------- #
# Configuration & result types
# --------------------------------------------------------------------------- #
@dataclass
class ScanConfig:
    start_url: str
    scope: list[str]                 # allowed hostnames (exact or suffix match)
    authorized: bool = False         # MUST be set True by an operator
    max_pages: int = 40
    delay: float = 0.3               # seconds between requests (be polite)
    timeout: float = 12.0
    crawl: bool = True
    include_forms: bool = True
    cookies: dict | None = None
    headers: dict | None = None
    user_agent: str = DEFAULT_UA
    verify_tls: bool = True
    attack_types: list[str] | None = None   # None = all; else subset of ATTACK_TYPES
    wordlist_files: list[str] | None = None  # None = all .txt lists when wordlist on
    max_wordlist: int = 250          # cap raw payloads fired per point (politeness)
    store_path: str | None = None    # SQLite path to persist this scan, or None
    verbose: bool = False            # log every probe/payload as it is fired
    verify: bool = False             # confirm execution in a headless browser (Playwright)
    waf_check: bool = True           # fingerprint the WAF/firewall first, then adapt
    recon: bool = True               # fingerprint stack + analyse security headers
    header_xss: bool = True          # test XSS via HTTP request headers
    multi_payload: bool = True       # keep firing after a hit; record several per point
    max_findings_per_point: int = 6  # cap distinct confirmed findings per injection point
    confirm_repeat: int = 3          # re-verify each hit this many times (clamped 3..6)
    waf_bypass_retry: bool = True    # on a WAF block, retry obfuscated variants (coverage test)


@dataclass
class Finding:
    url: str
    method: str
    parameter: str
    context: str
    payload_name: str
    payload: str
    severity: str
    evidence: str
    note: str = ""
    attack_type: str = "reflected"
    poc: str = ""          # ready-to-run proof (clickable URL or curl command)


@dataclass
class ScanResult:
    config_url: str
    pages_crawled: int = 0
    params_tested: int = 0
    requests_made: int = 0
    findings: list[Finding] = field(default_factory=list)
    reflections: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    recon: dict = field(default_factory=dict)   # server/tech fingerprint
    waf: dict = field(default_factory=dict)      # WAF profile
    started: float = 0.0
    finished: float = 0.0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = round((self.finished or time.time()) - self.started, 2)
        return d


class ScopeError(RuntimeError):
    pass


class AuthorizationError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Scope enforcement — the guardrail that keeps this a VAPT tool
# --------------------------------------------------------------------------- #
def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def normalize_scope_entry(entry: str) -> str:
    """Reduce a scope entry to a bare hostname.

    Operators often paste a full URL (``https://site.com/path?x=1``) or a
    host:port into the scope box; we forgivingly extract just the hostname so
    the scope guard still matches instead of refusing the scan.
    """
    a = (entry or "").lower().strip()
    if not a:
        return ""
    if "://" in a:
        return (urlparse(a).hostname or "").strip()
    # strip any path, query, fragment, or :port that was pasted in
    a = a.split("/")[0].split("?")[0].split("#")[0]
    if a.count(":") == 1:          # host:port (ignore IPv6 with many colons)
        a = a.split(":")[0]
    return a


def in_scope(url: str, scope: Iterable[str]) -> bool:
    h = _host(url)
    if not h:
        return False
    for allowed in scope:
        a = normalize_scope_entry(allowed)
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    return False


# --------------------------------------------------------------------------- #
# Reflection / context analysis
# --------------------------------------------------------------------------- #
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def detect_context(body: str, canary: str) -> str:
    """Classify the reflection context of `canary` within `body`.

    Returns one of: html, attr_double, attr_single, script, none.
    Picks the first (and typically most exploitable) occurrence.
    """
    idx = body.find(canary)
    if idx == -1:
        return "none"

    # Inside a <script> block?
    for m in _SCRIPT_BLOCK.finditer(body):
        if m.start(1) <= idx <= m.end(1):
            return "script"

    # Look at the current open tag (if any) to the left of the canary.
    left = body[:idx]
    last_lt = left.rfind("<")
    last_gt = left.rfind(">")
    if last_lt > last_gt:
        # We are inside a tag: likely an attribute value. Which quote?
        tag_fragment = left[last_lt:]
        dq = tag_fragment.count('"')
        sq = tag_fragment.count("'")
        if dq % 2 == 1:
            return "attr_double"
        if sq % 2 == 1:
            return "attr_single"
        # Unquoted attribute — treat as double for breakout attempts.
        return "attr_double"

    return "html"


def _unescaped_present(body: str, marker: str) -> bool:
    """True only if `marker` appears literally AND not HTML-encoded.

    If the app escaped our angle brackets/quotes, the escaped form will be
    present instead of the raw marker — which is a *safe* result, not a finding.
    """
    if marker not in body:
        return False
    encoded = html.escape(marker, quote=True)
    if encoded == marker:
        return True  # nothing to encode; rely on raw presence
    # Raw marker present and differs from its encoded form => unescaped sink.
    return True


_CANARY_SLOT = re.compile(r"/\*talxss[0-9a-f]+\*/")
_EXEC_CALL = re.compile(r"window\.__talxss\([^)]*\)")


def make_poc(url: str, method: str, param: str, base_params: dict, payload_value: str) -> str:
    """Turn a benign test payload into a ready-to-run proof of concept.

    The marker/callback is swapped for ``alert(document.domain)`` — a harmless,
    visible demonstration (pops the origin, steals nothing) that the operator can
    paste into a browser (GET) or run with curl (header/POST) to reproduce the bug.
    """
    real = _CANARY_SLOT.sub("alert(document.domain)", payload_value)
    real = _EXEC_CALL.sub("alert(document.domain)", real)
    if param.startswith("header:"):
        hname = param.split(":", 1)[1]
        return f'curl -s "{url}" -H "{hname}: {real}"'
    base = url.split("?")[0]
    p = dict(base_params)
    p[param] = real
    if method == "POST":
        return f'curl -s -X POST "{base}" --data "{urlencode(p)}"'
    return base + "?" + urlencode(p)


# --------------------------------------------------------------------------- #
# Target model: an injectable parameter on a URL or form
# --------------------------------------------------------------------------- #
@dataclass
class InjectionPoint:
    url: str                 # action URL
    method: str              # GET or POST
    param: str               # parameter name being fuzzed
    base_params: dict        # other params held constant


class Scanner:
    def __init__(self, config: ScanConfig, logger: Callable[[str], None] | None = None):
        self.cfg = config
        self.log = logger or (lambda m: None)
        self.result = ScanResult(config_url=config.start_url)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        if config.headers:
            self.session.headers.update(config.headers)
        if config.cookies:
            self.session.cookies.update(config.cookies)
        self._seen_points: set[tuple] = set()
        self._visited_pages: list[str] = []          # GET-able URLs, for stored pass
        self._submitted: list[tuple[str, Payload, InjectionPoint]] = []  # canary,payload,point
        self._get_points: list[InjectionPoint] = []   # GET points, for browser verify
        self.attack_types = config.attack_types      # None = all
        # Honour "verify 3 times minimum, max 6".
        self.cfg.confirm_repeat = max(3, min(6, int(config.confirm_repeat)))

    # -- HTTP ------------------------------------------------------------- #
    def _request(self, method: str, url: str, params=None, data=None):
        self.result.requests_made += 1
        if self.cfg.delay:
            time.sleep(self.cfg.delay)
        return self.session.request(
            method, url, params=params, data=data,
            timeout=self.cfg.timeout, allow_redirects=True,
            verify=self.cfg.verify_tls,
        )

    # -- Crawl ------------------------------------------------------------ #
    def crawl(self) -> list[InjectionPoint]:
        start = self.cfg.start_url
        if not in_scope(start, self.cfg.scope):
            raise ScopeError(f"Start URL {start!r} is not within authorized scope {self.cfg.scope}")

        points: list[InjectionPoint] = []
        queue: deque[str] = deque([start])
        visited: set[str] = set()

        while queue and len(visited) < self.cfg.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            if not in_scope(url, self.cfg.scope):
                continue

            try:
                resp = self._request("GET", url)
            except requests.RequestException as e:
                self.result.errors.append(f"GET {url}: {e}")
                continue

            self.result.pages_crawled += 1
            if url not in self._visited_pages:
                self._visited_pages.append(url)
            self.log(f"[crawl] {url} ({resp.status_code})")

            # URL-parameter injection points
            for ip in self._points_from_url(url):
                self._add_point(points, ip)

            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            if self.cfg.include_forms:
                for ip in self._points_from_forms(url, soup):
                    self._add_point(points, ip)

            if self.cfg.crawl:
                for a in soup.find_all("a", href=True):
                    nxt = urljoin(url, a["href"]).split("#")[0]
                    if in_scope(nxt, self.cfg.scope) and nxt not in visited:
                        queue.append(nxt)

        return points

    def _points_from_url(self, url: str) -> list[InjectionPoint]:
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not qs:
            return []
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        out = []
        for name in qs:
            out.append(InjectionPoint(base, "GET", name, dict(qs)))
        return out

    def _points_from_forms(self, page_url: str, soup: BeautifulSoup) -> list[InjectionPoint]:
        out = []
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url).split("#")[0]
            if not in_scope(action, self.cfg.scope):
                continue
            method = (form.get("method") or "GET").upper()
            fields: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields[name] = inp.get("value") or "test"
            for name in fields:
                if (inp_type := _field_type(form, name)) in ("submit", "button", "hidden"):
                    continue
                out.append(InjectionPoint(action, method, name, dict(fields)))
        return out

    def _add_point(self, points: list[InjectionPoint], ip: InjectionPoint):
        key = (ip.url, ip.method, ip.param)
        if key not in self._seen_points:
            self._seen_points.add(key)
            points.append(ip)

    # -- Test ------------------------------------------------------------- #
    def _stored_enabled(self) -> bool:
        return self.attack_types is None or "stored" in self.attack_types

    def _vlog(self, msg: str) -> None:
        if self.cfg.verbose:
            self.log(msg)

    @staticmethod
    def _snip(s: str, n: int = 80) -> str:
        s = s.replace("\n", " ")
        return s if len(s) <= n else s[:n] + "…"

    def test_point(self, ip: InjectionPoint) -> None:
        if ip.method == "GET" and ip not in self._get_points:
            self._get_points.append(ip)
        canary = new_canary()
        probe = analyzer.build_char_probe(canary)  # all significant chars at once

        self._vlog(f"[probe] {ip.method} {ip.url} param={ip.param} canary={canary}")
        body = self._send(ip, probe)
        if body is None:
            self._vlog("  └─ no response")
            return
        self.result.params_tested += 1
        self._vlog(f"  └─ reflected={'YES' if canary in body else 'no'}")

        # Stored XSS: submit persistence payloads NOW, regardless of whether the
        # immediate response reflects them. They are hunted for later, on other
        # pages, by stored_pass(). This is what catches guestbook/comment sinks.
        if self._stored_enabled():
            for sp in stored_payloads(canary, self.attack_types):
                self._submitted.append((canary, sp, ip))
                self._vlog(f"[fire] [stored] {ip.method} {ip.url} param={ip.param} "
                           f"payload={self._snip(sp.value)}")
                self._send(ip, sp.value)

        if canary not in body:
            return  # not reflected here -> only the stored path (above) applies

        context = detect_context(body, canary)
        self.result.reflections.append(
            {"url": ip.url, "method": ip.method, "param": ip.param, "context": context}
        )
        self.log(f"[reflect] {ip.method} {ip.url} param={ip.param} context={context}")
        if context == "none":
            return

        # ---- Reflection analysis: learn which characters survive unescaped ----
        prof = analyzer.analyze(body, canary, context)
        self.log(f"[analyze] {prof.summary()}")
        if not prof.can_inject_tag():
            self._vlog("  └─ < or > encoded here: tag injection blocked; "
                       "pruning to payloads that fit the surviving character set")

        # Context-aware payloads (reflected/cookie/dom/polyglot/waf); stored is
        # handled above, so drop it from the inline loop to avoid double-submits.
        inline_types = None
        if self.attack_types is not None:
            inline_types = [t for t in self.attack_types if t != "stored"]
        payloads = library_for_context(context, canary, inline_types)
        # Operator's curated wordlists, if the 'wordlist' attack type is enabled.
        if self.attack_types is None or "wordlist" in self.attack_types:
            payloads += load_wordlist_payloads(
                canary, self.cfg.wordlist_files, self.cfg.max_wordlist)

        found_here = 0
        blocked_any = False
        for payload in payloads:
            if found_here >= self.cfg.max_findings_per_point:
                self._vlog(f"  └─ reached cap of {self.cfg.max_findings_per_point} findings for this point")
                break
            # Navigational/text payloads (javascript:/vbscript:/markdown) reflect as
            # plain TEXT on any echoing endpoint — that is not XSS. Without an HTML-
            # active character (< > " ') there is no breakout to confirm by
            # reflection; such vectors need a URL/markdown sink and browser proof,
            # so don't reflection-confirm them here (prevents false positives).
            if not (set(payload.value) & {"<", ">", '"', "'"}):
                self._vlog(f"[skip] [{payload.attack_type}] navigational payload needs a "
                           f"URL/markdown sink + browser proof :: {self._snip(payload.value, 50)}")
                continue
            # Skip payloads whose required breakout chars are encoded here.
            if not analyzer.payload_feasible(payload.value, prof):
                self._vlog(f"[skip] [{payload.attack_type}] needs "
                           f"{''.join(analyzer.required_chars(payload.value))} "
                           f"(encoded) :: {self._snip(payload.value, 50)}")
                continue
            self._vlog(f"[fire] [{payload.attack_type}] {ip.method} {ip.url} "
                       f"param={ip.param} payload={self._snip(payload.value)}")
            status, resp_body = self._send_full(ip, payload.value)
            if resp_body is None:
                self._vlog("  └─ no response")
                continue

            # WAF block? Retry obfuscated variants and report which get through.
            if self._looks_blocked(status, resp_body):
                blocked_any = True
                self._vlog(f"  └─ blocked by WAF/firewall (HTTP {status})")
                if self.cfg.waf_bypass_retry and self._waf_bypass_attempt(ip, context, prof):
                    found_here += 1
                continue

            hit = _unescaped_present(resp_body, payload.confirm)
            self._vlog(f"  └─ {'UNESCAPED → vulnerable' if hit else 'encoded/not reflected'}")
            if hit:
                # Re-verify 3..6 times so a flaky/one-off reflection isn't reported.
                reps = self._reconfirm(ip, payload)
                self._vlog(f"  └─ re-verified {reps}/{self.cfg.confirm_repeat}")
                if reps < self.cfg.confirm_repeat:
                    self._vlog("  └─ not reproducible every time — not recorded")
                    continue
                self._record(ip, context, payload, resp_body,
                             reps=reps)
                self.log(f"[FOUND] {payload.severity.upper()} [{payload.attack_type}] "
                         f"{ip.method} {ip.url} param={ip.param} :: {payload.name} "
                         f"(verified {reps}/{self.cfg.confirm_repeat})")
                found_here += 1
                if not self.cfg.multi_payload and payload.attack_type != "cookie":
                    break  # single-finding mode: one solid hit is enough

        if blocked_any and found_here == 0:
            self._vlog("  └─ WAF blocked probes and no obfuscation variant got through here")

    def _send(self, ip: InjectionPoint, value: str) -> str | None:
        return self._send_full(ip, value)[1]

    def _send_full(self, ip: InjectionPoint, value: str) -> tuple[int | None, str | None]:
        """Send a payload; return (status_code, body) so callers can spot WAF blocks."""
        params = dict(ip.base_params)
        params[ip.param] = value
        try:
            if ip.method == "POST":
                resp = self._request("POST", ip.url, data=params)
            else:
                resp = self._request("GET", ip.url, params=params)
            return resp.status_code, resp.text
        except requests.RequestException as e:
            self.result.errors.append(f"{ip.method} {ip.url} [{ip.param}]: {e}")
            return None, None

    # A request looks WAF-blocked if the status is a classic block code or the
    # body carries a block-page marker (reuses the recon marker list).
    def _looks_blocked(self, status: int | None, body: str | None) -> bool:
        if status in (403, 406, 429, 501, 999):
            return True
        if body and any(m in body.lower() for m in _recon._BLOCK_MARKERS):
            return True
        return False

    def _reconfirm(self, ip: InjectionPoint, payload: Payload) -> int:
        """Re-fire a confirmed payload confirm_repeat times; return how many
        times it reproduced (stability check → kills flaky false positives)."""
        hits = 0
        for _ in range(self.cfg.confirm_repeat):
            body = self._send(ip, payload.value)
            if body is not None and _unescaped_present(body, payload.confirm):
                hits += 1
        return hits

    def _record(self, ip: InjectionPoint, context: str, payload: Payload, body: str,
                stored_url: str | None = None, reps: int | None = None,
                extra_note: str = ""):
        pos = body.find(payload.confirm)
        snippet = body[max(0, pos - 60): pos + len(payload.confirm) + 60]
        note = payload.note
        if stored_url:
            note = f"STORED: injected at {ip.url} [{ip.param}], resurfaced on {stored_url}. {note}"
        if extra_note:
            note = f"{extra_note} {note}".strip()
        if reps:
            note = f"{note} [re-verified {reps}/{self.cfg.confirm_repeat} times]".strip()
        self.result.findings.append(Finding(
            url=stored_url or ip.url, method=ip.method, parameter=ip.param, context=context,
            payload_name=payload.name, payload=payload.value,
            severity=payload.severity, note=note, attack_type=payload.attack_type,
            evidence="…" + snippet.replace("\n", " ") + "…",
            poc=make_poc(ip.url, ip.method, ip.param, ip.base_params, payload.value),
        ))

    # -- WAF-bypass retry (authorized WAF-coverage testing) --------------- #
    def _waf_bypass_attempt(self, ip: InjectionPoint, context: str,
                            prof) -> bool:
        """When the WAF blocked a payload, try the obfuscated 'waf-bypass'
        variants and report which (if any) got through UNblocked and reflected.

        This is coverage testing for an authorized engagement — it documents the
        gap in the WAF's rules so the defender can close it. Benign markers only.
        """
        canary = new_canary()
        variants = library_for_context(context, canary, ["waf-bypass"])
        for v in variants:
            self._vlog(f"[waf-bypass] trying {v.name}: {self._snip(v.value)}")
            status, body = self._send_full(ip, v.value)
            if body is None or self._looks_blocked(status, body):
                self._vlog("  └─ still blocked")
                continue
            if _unescaped_present(body, v.confirm):
                reps = self._reconfirm(ip, v)
                if reps >= self.cfg.confirm_repeat:
                    self._record(ip, context, v, body, reps=reps,
                                 extra_note=f"WAF BYPASSED via obfuscation ({v.name}) — "
                                            "the firewall blocked the plain payload but "
                                            "let this variant through. Harden the WAF rule.")
                    self.log(f"[BYPASS] {v.severity.upper()} [waf-bypass] {ip.method} "
                             f"{ip.url} param={ip.param} :: {v.name} "
                             f"(verified {reps}/{self.cfg.confirm_repeat})")
                    return True
        self._vlog("  └─ no obfuscation variant bypassed the WAF here")
        return False

    # -- Stored XSS pass -------------------------------------------------- #
    def stored_pass(self) -> None:
        """Re-fetch crawled pages and flag any submitted payload that resurfaced
        on a DIFFERENT page than where it was injected — the signature of stored XSS."""
        if not self._submitted:
            return
        self.log(f"[stored] re-checking {len(self._visited_pages)} page(s) for "
                 f"{len(self._submitted)} persisted payload(s)")
        for url in list(self._visited_pages):
            body = self._send_get(url)
            if body is None:
                continue
            for canary, payload, ip in self._submitted:
                if canary not in body:
                    continue
                # Different page than the injection action => stored, not reflected.
                if url.split("?")[0] == ip.url.split("?")[0]:
                    continue
                if _unescaped_present(body, payload.confirm):
                    self._record(ip, "html", payload, body, stored_url=url)
                    self.log(f"[FOUND] {payload.severity.upper()} [stored] "
                             f"{ip.url}[{ip.param}] -> {url} :: {payload.name}")

    def _send_get(self, url: str) -> str | None:
        try:
            return self._request("GET", url).text
        except requests.RequestException as e:
            self.result.errors.append(f"GET {url}: {e}")
            return None

    # -- Headless execution verification (real proof + DOM XSS) ----------- #
    def verify_pass(self) -> None:
        """Load each GET point in a real browser and confirm JS actually runs.

        This both upgrades reflected findings to CONFIRMED-execution and catches
        DOM-based XSS, where the sink is in client-side JS and never appears in
        the server's HTML (so reflection analysis alone cannot see it).
        """
        if not self._get_points:
            return
        if not _verify.available():
            self.log("[verify] Playwright not installed — skipping browser "
                     "verification. Enable with: pip install playwright && "
                     "python -m playwright install chromium")
            return
        self.log(f"[verify] headless-browser verification of {len(self._get_points)} GET point(s)")
        with _verify.Verifier(cookies=self.cfg.cookies, headers=self.cfg.headers,
                              verify_tls=self.cfg.verify_tls,
                              logger=self._vlog) as v:
            for ip in self._get_points:
                self._verify_point(ip, v)

    def _verify_point(self, ip: InjectionPoint, v) -> None:
        canary = new_canary()  # the exact token our JS will report back
        for payload in exec_payloads(canary, context="any"):
            url = _verify.exec_url(ip.url, ip.param, payload.value, ip.base_params)
            self._vlog(f"[verify] browser GET {ip.url} param={ip.param} "
                       f"payload={self._snip(payload.value)}")
            hit = v.executed(url, canary)
            if hit:
                origin = hit.split("|", 1)[1] if "|" in hit else "?"
                self.result.findings.append(Finding(
                    url=url, method="GET", parameter=ip.param, context="browser",
                    payload_name=payload.name, payload=payload.value,
                    severity="high", attack_type=payload.attack_type,
                    note=f"CONFIRMED: JavaScript executed in a headless browser (origin: {origin}).",
                    evidence=f"window.__talxss callback fired: {self._snip(hit, 60)}",
                    poc=make_poc(ip.url, "GET", ip.param, ip.base_params, payload.value),
                ))
                self.log(f"[CONFIRMED] HIGH [{payload.attack_type}] JS EXECUTED "
                         f"{ip.url} param={ip.param} origin={origin} :: {payload.name}")
                return  # one proven execution per point is enough

    # -- Recon & WAF (the professional's first moves) --------------------- #
    def recon_pass(self) -> None:
        """Fingerprint the stack, read security headers, and detect the WAF FIRST.

        A real black-box engagement starts here: know what's in front of the app
        before you poke it. WAF handling is detect-report-and-slow-down, never
        evasion. Honours scope/authorization via the normal request path.
        """
        base = self.cfg.start_url
        if not in_scope(base, self.cfg.scope):
            raise ScopeError(f"Start URL {base!r} is not within authorized scope {self.cfg.scope}")
        try:
            baseline = self._request("GET", base)
        except requests.RequestException as e:
            self.result.errors.append(f"recon GET {base}: {e}")
            return

        if self.cfg.recon:
            fp = _recon.fingerprint(baseline)
            self.result.recon = fp
            self.log(f"[recon] {fp}")
            for d in _recon.security_headers(baseline, url=base):
                self.result.findings.append(Finding(**d))
                self.log(f"[recon] {d['severity'].upper()} [security-header] {d['payload_name']}")

        if self.cfg.waf_check:
            prof = _recon.detect_waf(self._request, base, baseline, logger=self.log)
            self.result.waf = prof.as_dict()
            if prof.present:
                self.result.findings.append(Finding(
                    url=base, method="GET", parameter="-", context="recon",
                    payload_name=f"waf:{prof.name}", payload="", severity="low",
                    attack_type="waf", note="; ".join(prof.evidence) or "WAF fingerprinted.",
                    evidence=f"{prof.name} (confidence={prof.confidence}, blocking={prof.blocking})",
                ))
            # Adapt: if the WAF actively blocked a benign probe, slow down to be polite.
            if prof.blocking and self.cfg.delay < 1.0:
                self.cfg.delay = 1.0
                self.log("[waf] active blocking seen — throttling to 1.0s/request to be polite")

    # -- Header-based XSS ------------------------------------------------- #
    _HEADER_SINKS = ("User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host")

    def header_xss_pass(self) -> None:
        """Test XSS through request headers that apps often reflect (UA/Referer/XFF)."""
        if not self._visited_pages:
            return
        self.log(f"[header] testing {len(self._HEADER_SINKS)} header sink(s) across "
                 f"{len(self._visited_pages)} page(s)")
        for url in list(self._visited_pages):
            for header in self._HEADER_SINKS:
                self._test_header(url, header)

    def _test_header(self, url: str, header: str) -> None:
        canary = new_canary()
        probe = analyzer.build_char_probe(canary)
        try:
            resp = self._request_with_header("GET", url, header, probe)
        except requests.RequestException as e:
            self.result.errors.append(f"header {header} {url}: {e}")
            return
        body = resp.text
        self._vlog(f"[probe] HEADER {header} {url} canary={canary} "
                   f"reflected={'YES' if canary in body else 'no'}")
        if canary not in body:
            return
        context = detect_context(body, canary)
        if context == "none":
            return
        prof = analyzer.analyze(body, canary, context)
        self.log(f"[header] {header} reflected at {url} | {prof.summary()}")
        for payload in library_for_context(context, canary, ["reflected"]):
            if not analyzer.payload_feasible(payload.value, prof):
                continue
            try:
                rb = self._request_with_header("GET", url, header, payload.value).text
            except requests.RequestException:
                continue
            if _unescaped_present(rb, payload.confirm):
                pos = rb.find(payload.confirm)
                self.result.findings.append(Finding(
                    url=url, method="GET", parameter=f"header:{header}", context=context,
                    payload_name=payload.name, payload=payload.value, severity="high",
                    attack_type="header",
                    note=f"Reflected XSS via the {header} request header.",
                    evidence="…" + rb[max(0, pos - 50):pos + 80].replace("\n", " ") + "…",
                    poc=make_poc(url, "GET", f"header:{header}", {}, payload.value),
                ))
                self.log(f"[FOUND] HIGH [header] {header} @ {url} :: {payload.name}")
                return

    def _request_with_header(self, method: str, url: str, header: str, value: str):
        self.result.requests_made += 1
        if self.cfg.delay:
            time.sleep(self.cfg.delay)
        return self.session.request(method, url, headers={header: value},
                                    timeout=self.cfg.timeout, allow_redirects=True,
                                    verify=self.cfg.verify_tls)

    # -- Orchestration ---------------------------------------------------- #
    def run(self) -> ScanResult:
        if not self.cfg.authorized:
            raise AuthorizationError(
                "Scan refused: operator has not confirmed authorization for this target. "
                "Set authorized=True only when you have written permission to test it."
            )
        self.result.started = time.time()
        self.log(f"[start] TalXSS scan of {self.cfg.start_url} | scope={self.cfg.scope}")
        try:
            # Professional first moves: recon + WAF detection BEFORE any attacks.
            if self.cfg.recon or self.cfg.waf_check:
                self.recon_pass()
            points = self.crawl()
            self.log(f"[crawl] discovered {len(points)} injection point(s)")
            for ip in points:
                self.test_point(ip)
            # XSS via request headers (UA/Referer/XFF), if enabled.
            if self.cfg.header_xss and (self.attack_types is None
                                        or "header" in self.attack_types):
                self.header_xss_pass()
            # Stored XSS: did anything we submitted resurface elsewhere?
            if self.attack_types is None or "stored" in self.attack_types:
                self.stored_pass()
            # Real execution proof + DOM XSS, in a headless browser.
            if self.cfg.verify:
                self.verify_pass()
        finally:
            self.result.finished = time.time()
        self.log(f"[done] {len(self.result.findings)} finding(s), "
                 f"{self.result.requests_made} request(s)")

        if self.cfg.store_path:
            try:
                from .store import Store
                sid = Store(self.cfg.store_path).save_scan(
                    self.result, self.cfg.scope,
                    self.attack_types or ["(all)"])
                self.log(f"[store] saved scan #{sid} to {self.cfg.store_path}")
            except Exception as e:  # noqa: BLE001
                self.result.errors.append(f"store: {e}")
        return self.result


def _field_type(form, name: str) -> str:
    el = form.find(attrs={"name": name})
    if el is None:
        return ""
    return (el.get("type") or "").lower()
