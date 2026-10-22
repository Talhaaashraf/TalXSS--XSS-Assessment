"""Reflection analysis for TalXSS — the 'brain' that makes payload choice smart.

Before firing exploit payloads, TalXSS injects a single probe containing every
HTML/JS-significant character wrapped in canaries, then inspects the response to
learn EXACTLY which characters the application lets through unescaped. From that
it can:

  * explain why a point is or isn't exploitable (which chars are filtered),
  * skip payloads that cannot possibly work (needed char is encoded), and
  * prioritise payloads that fit the surviving character set.

This is what turns "I threw 1000 payloads and nothing happened" into
"< and > are HTML-encoded here, so tag injection is impossible; try the
attribute-breakout set instead."
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Characters that matter for breaking out of HTML/attribute/JS contexts.
PROBE_CHARS = ['<', '>', '"', "'", '`', '/', '\\', '(', ')', '{', '}', ';', '=', '&']


@dataclass
class ReflectionProfile:
    reflected: bool = False
    context: str = "none"
    survived: dict[str, bool] = field(default_factory=dict)  # char -> unescaped?

    @property
    def allowed(self) -> list[str]:
        return [c for c, ok in self.survived.items() if ok]

    @property
    def blocked(self) -> list[str]:
        return [c for c, ok in self.survived.items() if not ok]

    def can_inject_tag(self) -> bool:
        return self.survived.get('<', False) and self.survived.get('>', False)

    def summary(self) -> str:
        a = " ".join(self.allowed) or "(none)"
        b = " ".join(self.blocked) or "(none)"
        return f"context={self.context} | allowed: {a} | encoded: {b}"


def build_char_probe(canary: str) -> str:
    """A probe whose surviving characters we can isolate between two canaries."""
    return canary + "".join(PROBE_CHARS) + canary


def analyze(body: str, canary: str, context: str) -> ReflectionProfile:
    """Work out which probe characters came back unescaped between the canaries."""
    prof = ReflectionProfile(context=context)
    start = body.find(canary)
    if start == -1:
        return prof
    prof.reflected = True
    end = body.find(canary, start + len(canary))
    # The window between the two canaries is where our characters would land.
    window = body[start + len(canary): end] if end != -1 else body[start:start + 120]
    for ch in PROBE_CHARS:
        # Survived == the raw character is present in the reflected window.
        prof.survived[ch] = ch in window
    return prof


# Which probe characters a given payload string structurally depends on.
def required_chars(payload_value: str) -> list[str]:
    return [c for c in PROBE_CHARS if c in payload_value]


def payload_feasible(payload_value: str, prof: ReflectionProfile) -> bool:
    """True if every HTML-significant char the payload needs survived unescaped.

    If the profile shows no reflection data, we don't prune (fail open), so the
    scanner still behaves when analysis is inconclusive.
    """
    if not prof.survived:
        return True
    need = required_chars(payload_value)
    # Only prune on the structural breakout chars; ignore benign ones.
    critical = [c for c in need if c in ('<', '>', '"', "'", '`')]
    return all(prof.survived.get(c, True) for c in critical)
