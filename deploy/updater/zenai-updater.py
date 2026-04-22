#!/usr/bin/env python3
"""
ZenAI appliance updater agent.

Loops forever: register-if-needed -> checkin -> download -> verify -> apply -> report.
Designed to run as the systemd service `zenai-updater.service`.

Safety contract (from /home/net/Doc/UPDATE_SERVER_HANDOFF.md and prompt):
  * NEVER delete or mutate application data. We touch only the code tree.
  * apply_code MUST preserve .env, venv/, node_modules/, logs/, backups/, db.sqlite3.
  * Every terminal outcome (success, failed, rolled_back) MUST be reported.
  * Signature + SHA256 + file-level checksums verified before anything is applied.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Optional
from urllib import request as urlrequest
from urllib import error as urlerror

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("FATAL: python3-cryptography not installed. apt install python3-cryptography",
          file=sys.stderr)
    sys.exit(2)

STATE_DIR    = pathlib.Path(os.environ.get("ZENAI_STATE_DIR", "/opt/zenai/updater"))
STATE_FILE   = STATE_DIR / "state.json"
PUB_KEY_FILE = STATE_DIR / "keys" / "zentryc-zenai.pub"
LOG_FILE     = STATE_DIR / "logs" / "updater.log"
STAGING_DIR  = pathlib.Path(os.environ.get("ZENAI_STAGING_DIR", "/var/lib/zenai/updater/staging"))
BACKUP_DIR   = pathlib.Path(os.environ.get("ZENAI_BACKUP_DIR",  "/var/lib/zenai/updater/backups"))
API_BASE     = os.environ.get("ZENTRYC_API", "https://zentryc.com/api/v1")
AGENT_VER    = "0.1.0"
CHECK_INTERVAL_SEC = int(os.environ.get("ZENAI_CHECK_INTERVAL", "900"))
USER_AGENT   = f"zenai-updater/{AGENT_VER}"

for d in (STATE_DIR, STATE_DIR / "logs", STATE_DIR / "keys", STAGING_DIR, BACKUP_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("zenai-updater")


# ----------------------------------------------------------------------------
# HTTP helpers (stdlib only so we stay dependency-light in the agent)
# ----------------------------------------------------------------------------
def _request(method: str, url: str, headers: dict, body: Optional[bytes] = None,
             timeout: int = 60) -> tuple[int, bytes, dict]:
    req = urlrequest.Request(url, method=method, data=body)
    req.add_header("User-Agent", USER_AGENT)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urlerror.HTTPError as e:
        return e.code, e.read() or b"", dict(e.headers or {})


def _json_request(method: str, url: str, auth_headers: dict,
                  payload: Optional[dict] = None) -> tuple[int, Any]:
    headers = dict(auth_headers)
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    code, raw, _ = _request(method, url, headers, body)
    try:
        return code, json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return code, {"_raw": raw.decode("utf-8", errors="replace")}


def _download_file(url: str, auth_headers: dict, out_path: pathlib.Path,
                   expected_size: int, timeout: int = 600) -> None:
    headers = dict(auth_headers)
    headers["User-Agent"] = USER_AGENT
    req = urlrequest.Request(url, headers=headers)
    with urlrequest.urlopen(req, timeout=timeout) as resp, open(out_path, "wb") as fh:
        shutil.copyfileobj(resp, fh, length=1024 * 1024)
    actual = out_path.stat().st_size
    if actual != expected_size:
        raise RuntimeError(f"size mismatch: got {actual}, expected {expected_size}")


# ----------------------------------------------------------------------------
# State
# ----------------------------------------------------------------------------
def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        log.exception("state.json unreadable; treating as empty")
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    # 0640 so processes in the zenai-updater group (the FastAPI web
    # user is added to it at install time) can read the state for the
    # /system/updates UI. The file still contains api_key, but the web
    # handler strips it before serialising to clients (see
    # fastapi_app/api/updates.py :: _redact).
    os.chmod(tmp, 0o640)
    tmp.replace(STATE_FILE)


# ----------------------------------------------------------------------------
# Registration (first boot only)
# ----------------------------------------------------------------------------
def ensure_registered(state: dict, registration_token: Optional[str]) -> dict:
    if state.get("appliance_id") and state.get("api_key"):
        return state

    if not registration_token:
        log.error("Not registered, and ZENAI_REG_TOKEN is not set. "
                  "Set it once (systemctl set-environment ZENAI_REG_TOKEN=...) "
                  "then restart the service.")
        raise SystemExit(0)  # exit cleanly; service will retry via Restart=on-failure

    payload = {
        "registration_token": registration_token,
        "hostname": socket.gethostname(),
        "arch": "amd64",
        "os_version": _read_os_release(),
        "current_version": state.get("current_version", "0.0.0"),
    }
    code, resp = _json_request("POST", f"{API_BASE}/appliances/register", {}, payload)
    if code != 200:
        raise RuntimeError(f"register failed: HTTP {code} {resp}")

    state["appliance_id"]    = resp["appliance_id"]
    state["api_key"]         = resp["api_key"]
    state["current_version"] = state.get("current_version", "0.0.0")
    state["registered_at"]   = datetime.now(timezone.utc).isoformat()
    save_state(state)
    log.info("registered: appliance_id=%s", state["appliance_id"])
    return state


def _read_os_release() -> str:
    try:
        for line in pathlib.Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return "linux"


# ----------------------------------------------------------------------------
# Checkin + update offer
# ----------------------------------------------------------------------------
def auth_headers(state: dict) -> dict:
    return {
        "X-Appliance-ID": state["appliance_id"],
        "Authorization":  f"Bearer {state['api_key']}",
    }


def checkin(state: dict) -> dict:
    uptime_sec = 0
    try:
        uptime_sec = int(float(pathlib.Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        pass

    payload = {
        "hostname":        socket.gethostname(),
        "current_version": state.get("current_version", "0.0.0"),
        "agent_version":   AGENT_VER,
        "uptime":          uptime_sec,
        "services_status": _services_status(),
    }
    code, resp = _json_request("POST", f"{API_BASE}/appliances/checkin",
                               auth_headers(state), payload)
    if code != 200:
        log.warning("checkin failed: HTTP %s %s", code, resp)
        return {"next_action": "none"}
    state["last_checkin_at"] = datetime.now(timezone.utc).isoformat()
    if "subscription" in resp:
        state["subscription"] = resp["subscription"]
    save_state(state)
    return resp


def _services_status() -> dict:
    out = {}
    for svc in ("zentryc-web", "zentryc-syslog", "netlogs-web", "netlogs-syslog"):
        r = subprocess.run(["systemctl", "is-active", svc],
                           capture_output=True, text=True)
        status = r.stdout.strip() or "unknown"
        if status != "unknown":
            out[svc] = status
    return out


# ----------------------------------------------------------------------------
# Download + verify
# ----------------------------------------------------------------------------
def download_and_verify(state: dict, release: dict) -> pathlib.Path:
    rid       = release["id"]
    exp_sha   = release["package_sha256"]
    exp_size  = int(release["size"])
    sig_b64   = release.get("manifest_sig") or ""
    url       = release["package_url"]

    zup = STAGING_DIR / f"update-{rid}.zup"
    log.info("downloading release %s (%s bytes) -> %s", release.get("version"), exp_size, zup)
    _download_file(url, auth_headers(state), zup, exp_size, timeout=1800)

    # SHA-256 check
    h = hashlib.sha256()
    with open(zup, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != exp_sha:
        raise RuntimeError(f"sha256 mismatch: got {h.hexdigest()} expected {exp_sha}")

    # Extract to a temp dir for signature + checksum verification
    extract_dir = STAGING_DIR / f"extract-{rid}"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    with tarfile.open(zup, "r:gz") as tf:
        _safe_extract(tf, extract_dir)

    # Signature check: manifest.json.sig inside the tar should equal the base64
    # signature the server handed us (belt + braces).
    sig_zup = (extract_dir / "manifest.json.sig").read_bytes()
    if sig_b64:
        try:
            sig_api = base64.b64decode(sig_b64)
        except Exception as e:
            raise RuntimeError(f"manifest_sig from server is not valid base64: {e}")
        if sig_zup != sig_api:
            raise RuntimeError("signature in package does not match signature returned by server")

    pub = load_pem_public_key(PUB_KEY_FILE.read_bytes())
    try:
        pub.verify(sig_zup, (extract_dir / "manifest.json").read_bytes())
    except InvalidSignature:
        raise RuntimeError("Ed25519 signature verification FAILED")

    # File-level checksums
    checksums_file = extract_dir / "checksums.sha256"
    cp = subprocess.run(["sha256sum", "-c", "--quiet", str(checksums_file)],
                        cwd=extract_dir, capture_output=True, text=True)
    if cp.returncode != 0:
        raise RuntimeError(f"inner checksums failed: {cp.stderr.strip()}")

    log.info("verified release %s (sha256 + ed25519 + inner checksums)", rid)
    return extract_dir


def _safe_extract(tar: tarfile.TarFile, target: pathlib.Path) -> None:
    target = target.resolve()
    for m in tar.getmembers():
        p = (target / m.name).resolve()
        if not str(p).startswith(str(target) + os.sep) and p != target:
            raise RuntimeError(f"refusing to extract outside target: {m.name}")
    tar.extractall(target)


# ----------------------------------------------------------------------------
# Apply + rollback
# ----------------------------------------------------------------------------
class ApplyError(RuntimeError):
    def __init__(self, step_idx: int, step_type: str, msg: str):
        super().__init__(f"step {step_idx} ({step_type}): {msg}")
        self.step_idx = step_idx
        self.step_type = step_type


def apply_release(extract_dir: pathlib.Path, release_id: str) -> dict:
    manifest = json.loads((extract_dir / "manifest.json").read_text())
    steps = manifest.get("steps", [])
    backup_slot = BACKUP_DIR / f"pre-{release_id}"
    state_marker = {"release_id": release_id, "started_at": datetime.now(timezone.utc).isoformat()}

    for idx, step in enumerate(steps):
        stype = step.get("type")
        log.info("apply step %d: %s", idx, stype)
        try:
            if stype == "stop_services":
                _systemctl("stop", step.get("services", []), step.get("best_effort", False))
            elif stype == "start_services":
                _systemctl("start", step.get("services", []), step.get("best_effort", False))
            elif stype == "backup":
                _backup(step, extract_dir, backup_slot, manifest.get("install_root"))
            elif stype == "apply_code":
                _apply_code(step, extract_dir)
            elif stype == "pip_install":
                _pip_install(step)
            elif stype == "install_binary":
                _install_binary(step, extract_dir)
            elif stype == "health_check":
                _health_check(step)
            else:
                log.warning("unknown step type %s — skipping", stype)
        except Exception as e:
            raise ApplyError(idx, stype or "unknown", str(e)) from e

    return {"backup_slot": str(backup_slot), "manifest": manifest}


def _systemctl(action: str, services: list[str], best_effort: bool) -> None:
    for svc in services:
        r = subprocess.run(["systemctl", action, svc], capture_output=True, text=True)
        if r.returncode != 0:
            msg = f"systemctl {action} {svc}: {r.stderr.strip()}"
            if not best_effort:
                raise RuntimeError(msg)
            log.warning(msg)


def _backup(step: dict, extract_dir: pathlib.Path, slot: pathlib.Path,
            install_root: Optional[str]) -> None:
    slot.mkdir(parents=True, exist_ok=True)
    targets = step.get("targets", ["code"])
    if "code" in targets and install_root and os.path.isdir(install_root):
        archive = slot / "code.tar.gz"
        log.info("snapshotting %s -> %s", install_root, archive)
        subprocess.run(
            ["tar", "-czf", str(archive),
             "--exclude=venv", "--exclude=node_modules",
             "--exclude=logs", "--exclude=backups", "--exclude=__pycache__",
             "--exclude=.git",
             "-C", str(pathlib.Path(install_root).parent),
             pathlib.Path(install_root).name],
            check=True,
        )
    # NOTE: we deliberately DO NOT snapshot the database here. DB data is large,
    # out-of-scope for a code-only update, and preserved by apply_code's allowlist.


def _apply_code(step: dict, extract_dir: pathlib.Path) -> None:
    src = extract_dir / step.get("source", "payload")
    dst = pathlib.Path(step["destination"])
    if not src.is_dir():
        raise RuntimeError(f"apply_code: source missing: {src}")
    dst.mkdir(parents=True, exist_ok=True)
    preserve = [p.rstrip("/") for p in step.get("preserve", [])]

    # Build the rsync excludes from the preserve list so they are NOT overwritten.
    exclude_args = []
    for p in preserve:
        exclude_args += ["--exclude", p]

    log.info("rsync %s/ -> %s/  (preserve=%s)", src, dst, preserve)
    subprocess.run(
        ["rsync", "-a", "--delete", *exclude_args, f"{src}/", f"{dst}/"],
        check=True,
    )


def _pip_install(step: dict) -> None:
    venv = pathlib.Path(step["venv"])
    pip = venv / "bin" / "pip"
    req = step.get("requirements")
    if not pip.exists():
        if step.get("optional"):
            log.warning("venv pip missing (%s), skipping optional pip_install", pip)
            return
        raise RuntimeError(f"venv pip missing: {pip}")
    if req and pathlib.Path(req).is_file():
        subprocess.run([str(pip), "install", "--quiet", "-r", req], check=True)
    else:
        log.warning("pip_install: requirements not found (%s), skipping", req)


def _install_binary(step: dict, extract_dir: pathlib.Path) -> None:
    src = extract_dir / step["source"]
    dst = pathlib.Path(step["destination"])
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    dst.chmod(0o755)


def _health_check(step: dict) -> None:
    url = step["url"]
    timeout = int(step.get("timeout", 30))
    retries = int(step.get("retries", 1))
    last = ""
    for attempt in range(retries):
        try:
            code, body, _ = _request("GET", url, {}, timeout=timeout)
            if 200 <= code < 300:
                return
            last = f"HTTP {code}: {body[:200]!r}"
        except Exception as e:
            last = str(e)
        time.sleep(min(10, 2 ** attempt))
    raise RuntimeError(f"health_check failed after {retries} attempts: {last}")


def rollback(backup_slot: pathlib.Path, manifest: dict) -> None:
    install_root = manifest.get("install_root")
    archive = backup_slot / "code.tar.gz"
    if not archive.exists() or not install_root:
        log.error("rollback: no backup to restore from %s", archive)
        return
    log.info("rollback: restoring %s", install_root)
    subprocess.run(
        ["tar", "-xzf", str(archive), "-C", str(pathlib.Path(install_root).parent)],
        check=True,
    )
    for step in manifest.get("rollback_steps", []):
        if step.get("type") == "start_services":
            _systemctl("start", step.get("services", []), step.get("best_effort", True))


# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------
def report(state: dict, release_id: str, status: str,
           from_version: str, to_version: str,
           duration_sec: int, error_message: Optional[str] = None) -> None:
    payload = {
        "release_id":    release_id,
        "status":        status,
        "from_version":  from_version,
        "to_version":    to_version,
        "duration_sec":  duration_sec,
        "error_message": error_message,
    }
    code, resp = _json_request("POST", f"{API_BASE}/updates/report",
                               auth_headers(state), payload)
    log.info("report(%s) -> HTTP %s %s", status, code, resp)


# ----------------------------------------------------------------------------
# Main loop + one-shot commands
# ----------------------------------------------------------------------------
def run_once(force_apply: bool = False, dry_run: bool = False) -> int:
    state = load_state()
    state = ensure_registered(state, os.environ.get("ZENAI_REG_TOKEN"))
    resp = checkin(state)
    next_action = resp.get("next_action", "none")
    log.info("checkin next_action=%s", next_action)

    if next_action != "update" and not force_apply:
        return 0

    release = resp.get("release") or {}
    if not release:
        log.info("no release offered; nothing to do")
        return 0

    state["pending_release"] = release
    save_state(state)

    if dry_run:
        log.info("dry-run: skipping download/apply, leaving pending_release set")
        return 0

    started = time.monotonic()
    rid = release["id"]
    to_version = release.get("version", "unknown")
    from_version = state.get("current_version", "0.0.0")

    try:
        extract_dir = download_and_verify(state, release)
    except Exception as e:
        log.exception("download/verify failed")
        report(state, rid, "failed", from_version, to_version,
               int(time.monotonic() - started), f"download/verify: {e}")
        return 2

    try:
        result = apply_release(extract_dir, rid)
    except ApplyError as e:
        log.exception("apply failed")
        # Best-effort rollback from the backup slot we just created (if any)
        try:
            manifest = json.loads((extract_dir / "manifest.json").read_text())
            backup_slot = BACKUP_DIR / f"pre-{rid}"
            rollback(backup_slot, manifest)
            report(state, rid, "rolled_back", from_version, from_version,
                   int(time.monotonic() - started), str(e))
        except Exception:
            log.exception("rollback itself failed")
            report(state, rid, "failed", from_version, to_version,
                   int(time.monotonic() - started), f"apply+rollback: {e}")
        return 3

    state["current_version"] = to_version
    state["last_apply_at"]   = datetime.now(timezone.utc).isoformat()
    state["pending_release"] = None
    state.setdefault("history", []).insert(0, {
        "release_id":   rid,
        "version":      to_version,
        "applied_at":   state["last_apply_at"],
        "status":       "success",
    })
    state["history"] = state["history"][:20]
    save_state(state)

    report(state, rid, "success", from_version, to_version,
           int(time.monotonic() - started), None)
    log.info("applied %s successfully (%s -> %s)", rid, from_version, to_version)
    return 0


def loop_forever() -> None:
    stop = {"run": True}
    def _sig(_signum, _frame): stop["run"] = False
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    while stop["run"]:
        try:
            run_once()
        except SystemExit:
            raise
        except Exception:
            log.exception("unhandled exception in run_once")
        # Sleep in small slices so SIGTERM is responsive.
        for _ in range(CHECK_INTERVAL_SEC):
            if not stop["run"]:
                break
            time.sleep(1)


def main() -> int:
    ap = argparse.ArgumentParser(prog="zenai-updater")
    ap.add_argument("command", nargs="?", default="loop",
                    choices=["loop", "once", "checkin", "status", "register"])
    ap.add_argument("--dry-run", action="store_true", help="Run once but don't apply")
    ap.add_argument("--force", action="store_true", help="Apply pending release even if checkin says none")
    args = ap.parse_args()

    if args.command == "loop":
        loop_forever()
        return 0
    if args.command == "once":
        return run_once(force_apply=args.force, dry_run=args.dry_run)
    if args.command == "checkin":
        state = load_state()
        state = ensure_registered(state, os.environ.get("ZENAI_REG_TOKEN"))
        print(json.dumps(checkin(state), indent=2))
        return 0
    if args.command == "status":
        state = load_state()
        print(json.dumps({
            "appliance_id":     state.get("appliance_id"),
            "current_version":  state.get("current_version"),
            "last_checkin_at":  state.get("last_checkin_at"),
            "last_apply_at":    state.get("last_apply_at"),
            "pending_release":  state.get("pending_release"),
            "subscription":     state.get("subscription"),
            "history":          state.get("history", [])[:5],
            "api_base":         API_BASE,
        }, indent=2))
        return 0
    if args.command == "register":
        state = load_state()
        ensure_registered(state, os.environ.get("ZENAI_REG_TOKEN"))
        return 0
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
