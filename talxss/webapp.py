"""TalXSS web UI — a local control panel for running authorized XSS assessments.

Run:  python -m talxss.webapp      (serves http://127.0.0.1:5000)

The server binds to localhost only. It never scans anything until an operator
ticks the authorization box and supplies an explicit host scope.
"""

from __future__ import annotations

import threading
import uuid
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template, Response

from . import __version__
from .scanner import Scanner, ScanConfig, AuthorizationError, ScopeError
from .report import to_html, to_json
from .payloads import ATTACK_TYPES, available_wordlists
from .store import Store, DEFAULT_DB

app = Flask(__name__)

# In-memory job registry (single-user local tool).
_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _run_job(job_id: str, cfg: ScanConfig):
    job = _JOBS[job_id]

    def log(msg: str):
        with _LOCK:
            job["log"].append(msg)
            job["log"] = job["log"][-400:]

    try:
        scanner = Scanner(cfg, logger=log)
        result = scanner.run()
        with _LOCK:
            job["result"] = result
            job["status"] = "done"
            job["summary"] = result.as_dict()
    except (AuthorizationError, ScopeError) as e:
        with _LOCK:
            job["status"] = "refused"
            job["error"] = str(e)
    except Exception as e:  # noqa: BLE001 - surface any engine error to the UI
        with _LOCK:
            job["status"] = "error"
            job["error"] = f"{type(e).__name__}: {e}"


@app.route("/")
def index():
    return render_template("index.html", version=__version__,
                           attack_types=ATTACK_TYPES, wordlists=available_wordlists())


@app.get("/api/wordlists")
def wordlists():
    return jsonify(attack_types=ATTACK_TYPES, wordlists=available_wordlists())


@app.get("/api/history")
def history():
    return jsonify(scans=Store(DEFAULT_DB).list_scans())


@app.get("/api/history/<int:scan_id>")
def history_scan(scan_id: int):
    scan = Store(DEFAULT_DB).get_scan(scan_id)
    if not scan:
        return jsonify(error="Not found."), 404
    return jsonify(scan=scan)


@app.post("/api/scan")
def start_scan():
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify(error="A target URL is required."), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    if not data.get("authorized"):
        return jsonify(error="You must confirm you are authorized to test this target."), 403

    # Default scope = the target's own host, unless the operator narrows/sets it.
    scope_raw = (data.get("scope") or "").strip()
    if scope_raw:
        scope = [s.strip() for s in scope_raw.replace(",", " ").split() if s.strip()]
    else:
        scope = [urlparse(target).hostname or ""]
    scope = [s for s in scope if s]
    if not scope:
        return jsonify(error="Could not determine a valid scope host."), 400

    cookies = _parse_kv(data.get("cookies", ""))
    headers = _parse_kv(data.get("headers", ""), sep=":")

    attack_types = data.get("attack_types") or None
    if attack_types:
        attack_types = [t for t in attack_types if t in ATTACK_TYPES]
    wordlists = data.get("wordlists") or None

    cfg = ScanConfig(
        start_url=target,
        scope=scope,
        authorized=True,
        max_pages=int(data.get("max_pages", 40)),
        delay=float(data.get("delay", 0.3)),
        crawl=bool(data.get("crawl", True)),
        include_forms=bool(data.get("include_forms", True)),
        cookies=cookies or None,
        headers=headers or None,
        verify_tls=bool(data.get("verify_tls", True)),
        attack_types=attack_types,
        wordlist_files=wordlists,
        max_wordlist=int(data.get("max_wordlist", 250)),
        store_path=None if data.get("no_store") else str(DEFAULT_DB),
        verbose=bool(data.get("verbose", True)),
        verify=bool(data.get("verify", False)),
    )

    job_id = uuid.uuid4().hex[:12]
    _JOBS[job_id] = {"status": "running", "log": [], "result": None,
                     "error": None, "summary": None, "target": target}
    threading.Thread(target=_run_job, args=(job_id, cfg), daemon=True).start()
    return jsonify(job_id=job_id, scope=scope)


@app.get("/api/status/<job_id>")
def status(job_id: str):
    job = _JOBS.get(job_id)
    if not job:
        return jsonify(error="Unknown job."), 404
    with _LOCK:
        findings = []
        if job["result"]:
            findings = [vars(f) for f in job["result"].findings]
        return jsonify(
            status=job["status"], log=job["log"], error=job["error"],
            summary=job["summary"], findings=findings,
        )


@app.get("/api/report/<job_id>.<fmt>")
def report(job_id: str, fmt: str):
    job = _JOBS.get(job_id)
    if not job or not job.get("result"):
        return jsonify(error="No completed scan for this job."), 404
    if fmt == "json":
        return Response(to_json(job["result"]), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=talxss-{job_id}.json"})
    if fmt == "html":
        return Response(to_html(job["result"], __version__), mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename=talxss-{job_id}.html"})
    return jsonify(error="Unknown format."), 400


def _parse_kv(raw: str, sep: str = "=") -> dict:
    out: dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or sep not in line:
            continue
        k, v = line.split(sep, 1)
        out[k.strip()] = v.strip()
    return out


def main():
    print(f"TalXSS v{__version__} — local control panel at http://127.0.0.1:5000")
    print("Authorized assessments only. Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
