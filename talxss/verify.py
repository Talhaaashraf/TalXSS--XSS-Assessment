"""Headless-browser execution verification for TalXSS.

Reflection analysis tells us a payload *should* fire; this module proves it
*does* by loading the injected page in a real headless Chromium and watching
for our canary to execute JavaScript. That upgrades a finding from
"input reflected unescaped" (good) to "JavaScript executed in the browser"
(undeniable) — and it is the only way to confirm DOM-based XSS, where the sink
is in client-side JS and never appears in the raw HTML response.

Playwright is optional. If it is not installed, verification is skipped and the
scanner falls back to reflection-based confirmation. To enable:

    pip install playwright
    python -m playwright install chromium
"""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def exec_url(base_url: str, param: str, payload: str, base_params: dict | None = None) -> str:
    """Build a GET URL with `payload` placed in `param`."""
    parsed = urlparse(base_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if base_params:
        params.update(base_params)
    params[param] = payload
    return urlunparse(parsed._replace(query=urlencode(params)))


class Verifier:
    """Confirms a canary actually executed JavaScript in a headless browser."""

    def __init__(self, cookies: dict | None = None, headers: dict | None = None,
                 verify_tls: bool = True, timeout: float = 8.0,
                 logger=None):
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.verify_tls = verify_tls
        self.timeout_ms = int(timeout * 1000)
        self.log = logger or (lambda m: None)
        self._pw = None
        self._browser = None

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        return self

    def __exit__(self, *exc):
        try:
            if self._browser:
                self._browser.close()
        finally:
            if self._pw:
                self._pw.stop()

    def _new_page(self, start_url: str):
        ctx = self._browser.new_context(
            ignore_https_errors=not self.verify_tls,
            extra_http_headers=self.headers or None,
        )
        if self.cookies:
            host = urlparse(start_url).hostname or ""
            ctx.add_cookies([{"name": k, "value": v, "domain": host, "path": "/"}
                             for k, v in self.cookies.items()])
        page = ctx.new_page()
        # Capture both alert()/confirm()/prompt() dialogs and a hooked marker.
        hits: list[str] = []
        page.on("dialog", lambda d: (hits.append(str(d.message)), d.dismiss()))
        page.add_init_script(
            "window.__talxss=function(m){(window.__TALXSS_HITS=window.__TALXSS_HITS||[]).push(''+m)};"
        )
        return ctx, page, hits

    def executed(self, start_url: str, canary: str) -> str | None:
        """Load `start_url` headless; return the matched callback message if
        `canary` ran JavaScript (e.g. ``<canary>|example.com``), else None.

        A truthy return still works as a boolean 'did it fire?', but the string
        also carries the origin the payload executed in — stronger report evidence.
        """
        ctx = page = None
        try:
            ctx, page, hits = self._new_page(start_url)
            try:
                page.goto(start_url, wait_until="load", timeout=self.timeout_ms)
                page.wait_for_timeout(600)  # let onload/async sinks fire
            except Exception as e:  # navigation/timeout: still inspect what ran
                self.log(f"  └─ nav note: {type(e).__name__}")
            try:
                marker = page.evaluate("window.__TALXSS_HITS || []")
            except Exception:
                marker = []
            for h in list(hits) + [str(m) for m in marker]:
                if canary in h:
                    return h
            return None
        except Exception as e:  # noqa: BLE001
            self.log(f"  └─ verify error: {type(e).__name__}: {e}")
            return None
        finally:
            try:
                if ctx:
                    ctx.close()
            except Exception:
                pass
