from __future__ import annotations

import asyncio
import difflib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
import yaml
from aiohttp import web


BASE_DIR = Path("/opt/ha_expert")
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path("/data")
STATE_FILE = DATA_DIR / "ha_expert_state.json"
INTERNAL_HA_URL = os.environ.get("HA_EXPERT_INTERNAL_HA_URL", "http://homeassistant:8123")
INTERNAL_HA_PORT = int(os.environ.get("HA_EXPERT_INTERNAL_HA_PORT", "8123"))
OPERATOR_URL = os.environ.get("HA_EXPERT_OPERATOR_URL", "http://100.109.244.70:8788").rstrip("/")
HEARTBEAT_SECONDS = 15
TAILSCALE_AUTHKEY = os.environ.get("HA_EXPERT_TAILSCALE_AUTHKEY", "").strip()
MISSING_TAILSCALE_KEY_ERROR = "Brak skonfigurowanego klucza Tailscale po stronie dodatku."
TAILSCALE_TAG_NOT_PERMITTED_MARKERS = (
    "requested tags",
    "invalid or not permitted",
)
CONFIGURED_CLIENT_LOGIN = os.environ.get("HA_EXPERT_CLIENT_LOGIN", "").strip()
CONFIGURED_HA_TOKEN = os.environ.get("HA_EXPERT_HA_TOKEN", "").strip()
TAILSCALE_TAG = os.environ.get("HA_EXPERT_TAILSCALE_TAG", "tag:ha-expert-client").strip() or "tag:ha-expert-client"
TAILSCALE_HOST_PREFIX = os.environ.get("HA_EXPERT_TAILSCALE_HOST_PREFIX", "ha-expert").strip() or "ha-expert"
TAILSCALE_STATE_DIR = Path(os.environ.get("HA_EXPERT_TAILSCALE_STATE_DIR", "/data/tailscale"))
TAILSCALE_SOCKET = os.environ.get("HA_EXPERT_TAILSCALE_SOCKET", "/data/tailscale/tailscaled.sock").strip()
TAILSCALE_SOCKS5_SERVER = os.environ.get("HA_EXPERT_TAILSCALE_SOCKS5_SERVER", "127.0.0.1:1055").strip()
TAILSCALE_HTTP_PROXY = os.environ.get("HA_EXPERT_TAILSCALE_HTTP_PROXY", "http://127.0.0.1:1056").strip()
HOME_ASSISTANT_LOG_DIR = Path("/homeassistant")
AUTOMATIONS_FILE = HOME_ASSISTANT_LOG_DIR / "automations.yaml"
SCRIPTS_FILE = HOME_ASSISTANT_LOG_DIR / "scripts.yaml"
DEFAULT_HA_LOG_LINES = 180
SUPERVISOR_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor").rstrip("/")
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "").strip()
ALLOWED_LOG_SEVERITIES = {"all", "warning", "error", "critical"}
HA_RELAY_HOST = "127.0.0.1"
HA_RELAY_PORT = int(os.environ.get("HA_EXPERT_HA_RELAY_PORT", "18123"))
HA_DASHBOARD_PORT = int(os.environ.get("HA_EXPERT_HA_DASHBOARD_PORT", "18123"))
HA_EXPERT_VERSION = "0.2.0-dev"
HA_EXPERT_NAMESPACE = Path("/homeassistant/.ha_expert")
HA_EXPERT_TX_DIR = HA_EXPERT_NAMESPACE / "transactions"
HA_EXPERT_MUTATION_LOCK = HA_EXPERT_NAMESPACE / "mutation.lock"
MUTATION_LOCK_STALE_SECONDS = 600
SUPPORTED_JOB_KINDS = {
    "client_capabilities",
    "ha_entity_report",
    "ha_delete_automation",
    "ha_delete_script",
    "ha_generate_automation",
    "ha_generate_script",
    "ha_get_state",
    "ha_find",
    "ha_get_automation",
    "ha_get_script",
    "ha_helper_list",
    "ha_last_trigger",
    "ha_logbook",
    "ha_log_tail",
    "ha_recent_changes",
    "ha_scan",
    "ha_service_call",
    "ha_set_helper",
    "ha_snapshot",
    "ha_state_history",
    "ha_test_auth",
    "ha_core_check",
    "ha_tx_list",
    "ha_tx_rollback",
    "ha_upsert_automation",
    "ha_upsert_script",
    "ha_validate_yaml",
    "ha_where_used",
    "ha_ws_call",
}


class TailscaleAdapter:
    def __init__(self) -> None:
        self._proc: subprocess.Popen[str] | None = None
        self.last_connect_warning = ""

    def available(self) -> bool:
        return shutil.which("tailscale") is not None and shutil.which("tailscaled") is not None

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["TS_SOCKET"] = TAILSCALE_SOCKET
        return env

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(args, capture_output=True, text=True, env=self._env())
        if check and proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip() or "Nieznany błąd Tailscale."
            raise RuntimeError(stderr)
        return proc

    async def _wait_local_api(self, timeout: float = 15.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            try:
                self._run(["tailscale", "--socket", TAILSCALE_SOCKET, "status", "--json"])
                return
            except Exception:
                await asyncio.sleep(0.5)
        raise RuntimeError("Tailscale nie uruchomił lokalnego API w oczekiwanym czasie.")

    async def start(self) -> None:
        if not self.available():
            raise RuntimeError("Brakuje binariów Tailscale w dodatku.")

        TAILSCALE_STATE_DIR.mkdir(parents=True, exist_ok=True)
        if self._proc and self._proc.poll() is None:
            return

        self._proc = subprocess.Popen(
            [
                "tailscaled",
                "--state",
                str(TAILSCALE_STATE_DIR / "tailscaled.state"),
                "--socket",
                TAILSCALE_SOCKET,
                "--tun=userspace-networking",
                f"--socks5-server={TAILSCALE_SOCKS5_SERVER}",
                f"--outbound-http-proxy-listen={TAILSCALE_HTTP_PROXY.removeprefix('http://')}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=self._env(),
        )
        await self._wait_local_api()

    @staticmethod
    def _sanitize_login(client_login: str) -> str:
        sanitized = re.sub(r"[^a-z0-9-]+", "-", client_login.lower()).strip("-")
        sanitized = re.sub(r"-{2,}", "-", sanitized)
        return sanitized or "klient"

    async def connect(self, client_login: str) -> dict[str, str]:
        if not TAILSCALE_AUTHKEY:
            raise RuntimeError(MISSING_TAILSCALE_KEY_ERROR)

        await self.start()
        hostname = f"{TAILSCALE_HOST_PREFIX}-{self._sanitize_login(client_login)}"
        self.last_connect_warning = ""
        args = [
            "tailscale",
            "--socket",
            TAILSCALE_SOCKET,
            "up",
            "--reset",
            f"--authkey={TAILSCALE_AUTHKEY}",
            f"--hostname={hostname}",
            "--accept-dns=false",
        ]
        if TAILSCALE_TAG:
            try:
                self._run(args + [f"--advertise-tags={TAILSCALE_TAG}"])
            except RuntimeError as exc:
                message = str(exc)
                lowered = message.lower()
                if all(marker in lowered for marker in TAILSCALE_TAG_NOT_PERMITTED_MARKERS):
                    self.last_connect_warning = (
                        f"Połączono bez tagu {TAILSCALE_TAG}, bo bieżąca polityka Tailscale nie pozwala go użyć."
                    )
                    self._run(args)
                else:
                    raise
        else:
            self._run(args)
        return await self.status()

    async def status(self) -> dict[str, str]:
        await self.start()
        status_raw = self._run(["tailscale", "--socket", TAILSCALE_SOCKET, "status", "--json"]).stdout
        data = json.loads(status_raw or "{}")
        ip_raw = self._run(["tailscale", "--socket", TAILSCALE_SOCKET, "ip", "-4"]).stdout.strip()
        tailscale_ip = ip_raw.splitlines()[0].strip() if ip_raw else ""
        tailscale_node = str(data.get("Self", {}).get("DNSName", "")).strip()
        backend_state = str(data.get("BackendState", "")).strip()
        connected = backend_state == "Running" and bool(tailscale_ip)
        return {
            "connected": "true" if connected else "false",
            "tailscale_ip": tailscale_ip,
            "tailscale_node": tailscale_node,
        }

    async def disconnect(self) -> None:
        if not self.available():
            return
        try:
            await self.start()
            self.reset_serve()
            self._run(["tailscale", "--socket", TAILSCALE_SOCKET, "logout"], check=False)
        finally:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    self._proc.kill()
            self._proc = None

    def reset_serve(self) -> None:
        self._run(["tailscale", "--socket", TAILSCALE_SOCKET, "serve", "reset"], check=False)


class LocalTcpRelay:
    def __init__(self) -> None:
        self._server: asyncio.base_events.Server | None = None

    @staticmethod
    def _target() -> tuple[str, int]:
        parsed = urlparse(INTERNAL_HA_URL)
        host = parsed.hostname or "homeassistant"
        port = parsed.port or INTERNAL_HA_PORT
        return host, port

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        target_host, target_port = self._target()
        try:
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        except Exception:
            client_writer.close()
            await client_writer.wait_closed()
            return

        upstream = asyncio.create_task(self._pipe(client_reader, target_writer))
        downstream = asyncio.create_task(self._pipe(target_reader, client_writer))
        done, pending = await asyncio.wait({upstream, downstream}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, return_exceptions=True)
        await asyncio.gather(*pending, return_exceptions=True)

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle_client, HA_RELAY_HOST, HA_RELAY_PORT)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None


def _ensure_state_file() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(
            json.dumps(
                {
                    "client_login": "",
                    "ha_token": "",
                    "connected": False,
                    "tailscale_ip": "",
                    "tailscale_node": "",
                    "dashboard_url": "",
                    "last_error": "",
                    "last_notice": "",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )


def _read_state() -> dict[str, Any]:
    _ensure_state_file()
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def _write_state(state: dict[str, Any]) -> None:
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _build_dashboard_url(tailscale_ip: str) -> str:
    tailscale_ip = tailscale_ip.strip()
    if not tailscale_ip:
        return ""
    return f"http://{tailscale_ip}:{HA_DASHBOARD_PORT}/"


def _resolve_ha_log_file() -> Path:
    candidates = sorted(
        HOME_ASSISTANT_LOG_DIR.glob("home-assistant.log*"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    raise RuntimeError("Nie znaleziono żadnego dostępnego pliku logu Home Assistant po stronie klienta.")


def _read_ha_log_tail_via_supervisor(lines: int = DEFAULT_HA_LOG_LINES) -> dict[str, Any]:
    if not SUPERVISOR_TOKEN:
        raise RuntimeError("Brak SUPERVISOR_TOKEN do pobrania logów przez Supervisor API.")
    query = urllib.parse.urlencode({"lines": lines})
    url = f"{SUPERVISOR_URL}/core/logs/latest?{query}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            text = response.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace").strip()
        raise RuntimeError(detail or f"Supervisor API zwrócił HTTP {exc.code} przy pobieraniu logów.") from exc
    except Exception as exc:
        raise RuntimeError("Nie udało się pobrać logów przez Supervisor API.") from exc

    if not text:
        raise RuntimeError("Supervisor API zwrócił pustą odpowiedź logów Home Assistant.")

    return {
        "source": "supervisor:/core/logs/latest",
        "lines": lines,
        "text": text,
    }


async def _supervisor_request(method: str, path: str, payload: dict[str, Any] | None = None, timeout_seconds: int = 120) -> Any:
    if not SUPERVISOR_TOKEN:
        raise RuntimeError("Brak SUPERVISOR_TOKEN do wykonania operacji Supervisor API.")
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    url = f"{SUPERVISOR_URL}{path}"
    headers = {"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.request(method, url, json=payload) as response:
            text = await response.text()
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = text
            if response.status >= 400:
                raise RuntimeError(f"Supervisor API zwróciło HTTP {response.status}: {data}")
            return data


async def _ha_core_check(_: dict[str, Any] | None = None) -> dict[str, Any]:
    data = await _supervisor_request("POST", "/core/check", {})
    ok = isinstance(data, dict) and data.get("result") == "ok"
    return {"ok": ok, "source": "supervisor:/core/check", "result": data}


def _filter_log_text(text: str, severity: str) -> str:
    severity = severity.strip().lower() or "all"
    if severity not in ALLOWED_LOG_SEVERITIES or severity == "all":
        return text

    marker_map = {
        "warning": " WARNING ",
        "error": " ERROR ",
        "critical": " CRITICAL ",
    }
    marker = marker_map[severity]
    selected = [line for line in text.splitlines() if marker in line]
    return "\n".join(selected)


def _read_ha_log_tail(lines: int = DEFAULT_HA_LOG_LINES, severity: str = "all") -> dict[str, Any]:
    lines = max(20, min(lines, 500))
    try:
        result = _read_ha_log_tail_via_supervisor(lines)
    except Exception:
        log_file = _resolve_ha_log_file()
        content = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = content[-lines:]
        result = {
            "source": str(log_file),
            "lines": lines,
            "text": "\n".join(selected),
        }
    severity = severity.strip().lower() or "all"
    filtered = _filter_log_text(str(result.get("text", "")), severity)
    result["severity"] = severity
    result["text"] = filtered or "Brak wpisów w wybranej kategorii logów."
    return result


def _client_capabilities() -> dict[str, Any]:
    return {
        "name": "HA Expert",
        "version": HA_EXPERT_VERSION,
        "namespace": str(HA_EXPERT_NAMESPACE),
        "job_kinds": sorted(SUPPORTED_JOB_KINDS),
        "runtime": {
            "ha_token_configured": bool(CONFIGURED_HA_TOKEN),
            "supervisor_token_available": bool(SUPERVISOR_TOKEN),
            "homeassistant_config_mapped": HOME_ASSISTANT_LOG_DIR.exists(),
        },
        "stable_jobs": ["ha_log_tail"],
        "experimental_jobs": sorted(SUPPORTED_JOB_KINDS - {"ha_log_tail"}),
    }


def _ha_headers() -> dict[str, str]:
    if not CONFIGURED_HA_TOKEN:
        raise RuntimeError("Brak ha_token do wykonania operacji runtime.")
    return {
        "Authorization": f"Bearer {CONFIGURED_HA_TOKEN}",
        "Content-Type": "application/json",
    }


async def _ha_request(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    timeout = aiohttp.ClientTimeout(total=30)
    url = f"{INTERNAL_HA_URL.rstrip('/')}{path}"
    async with aiohttp.ClientSession(timeout=timeout, headers=_ha_headers()) as session:
        async with session.request(method, url, json=payload) as response:
            text = await response.text()
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = text
            if response.status >= 400:
                raise RuntimeError(f"Home Assistant API zwróciło HTTP {response.status}: {data}")
            return data


def _ws_url_from_ha_url(ha_url: str) -> str:
    parsed = urlparse(ha_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}/api/websocket"


async def _ha_ws_call(message: dict[str, Any]) -> dict[str, Any]:
    if not CONFIGURED_HA_TOKEN:
        raise RuntimeError("Brak ha_token do wykonania operacji runtime.")
    timeout = aiohttp.ClientTimeout(total=30)
    body = dict(message)
    body.setdefault("id", 1)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.ws_connect(_ws_url_from_ha_url(INTERNAL_HA_URL)) as ws:
            first = await ws.receive_json()
            if first.get("type") != "auth_required":
                raise RuntimeError(f"Nieoczekiwana pierwsza ramka WS: {first}")
            await ws.send_json({"type": "auth", "access_token": CONFIGURED_HA_TOKEN})
            auth = await ws.receive_json()
            if auth.get("type") != "auth_ok":
                raise RuntimeError(f"Autoryzacja WS nie powiodła się: {auth}")
            await ws.send_json(body)
            while True:
                msg = await ws.receive_json()
                if msg.get("id") == body["id"]:
                    return msg


def _entity_ids_from_payload(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("entity_ids", payload.get("entity_id", []))
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise RuntimeError("entity_id albo entity_ids musi być listą lub tekstem.")
    entity_ids = [str(item).strip() for item in raw if str(item).strip()]
    if not entity_ids:
        raise RuntimeError("Podaj przynajmniej jedną encję.")
    return entity_ids


async def _ha_test_auth() -> dict[str, Any]:
    config = await _ha_request("GET", "/api/config")
    return {
        "ok": True,
        "ha_url": INTERNAL_HA_URL,
        "version": config.get("version") if isinstance(config, dict) else "",
        "location_name": config.get("location_name") if isinstance(config, dict) else "",
    }


async def _ha_get_state(payload: dict[str, Any]) -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    include_attributes = bool(payload.get("with_attributes", False))
    for entity_id in _entity_ids_from_payload(payload):
        quoted = urllib.parse.quote(entity_id, safe="")
        try:
            row = await _ha_request("GET", f"/api/states/{quoted}")
        except RuntimeError as exc:
            if "HTTP 404" not in str(exc):
                raise
            out.append({"entity_id": entity_id, "found": False})
            continue
        attrs = row.get("attributes", {}) if isinstance(row, dict) else {}
        item = {
            "entity_id": entity_id,
            "found": True,
            "state": row.get("state") if isinstance(row, dict) else "",
            "friendly_name": attrs.get("friendly_name", "") if isinstance(attrs, dict) else "",
        }
        if include_attributes:
            item["attributes"] = attrs
        out.append(item)
    return {"states": out}


def _parse_history_datetime(value: Any, default: datetime) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        return default
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise RuntimeError(f"Niepoprawny czas historii: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _history_window(payload: dict[str, Any], default_hours: float) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    hours = float(payload.get("hours", default_hours) or default_hours)
    hours = max(0.05, min(hours, 168.0))
    end = _parse_history_datetime(payload.get("end_time"), now)
    start = _parse_history_datetime(payload.get("start_time"), end - timedelta(hours=hours))
    if start >= end:
        raise RuntimeError("start_time musi być wcześniejszy niż end_time.")
    return start, end


def _simplify_history_rows(raw: Any, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entity_rows in raw if isinstance(raw, list) else []:
        if not isinstance(entity_rows, list):
            continue
        previous_state = None
        for row in entity_rows:
            if not isinstance(row, dict):
                continue
            attrs = row.get("attributes", {}) if isinstance(row.get("attributes"), dict) else {}
            state = row.get("state")
            rows.append(
                {
                    "entity_id": row.get("entity_id", ""),
                    "state": state,
                    "previous_state": previous_state,
                    "last_changed": row.get("last_changed", ""),
                    "last_updated": row.get("last_updated", ""),
                    "context_id": row.get("context", {}).get("id", "") if isinstance(row.get("context"), dict) else "",
                    "context_parent_id": row.get("context", {}).get("parent_id", "") if isinstance(row.get("context"), dict) else "",
                    "context_user_id": row.get("context", {}).get("user_id", "") if isinstance(row.get("context"), dict) else "",
                    "friendly_name": attrs.get("friendly_name", ""),
                }
            )
            previous_state = state
    rows.sort(key=lambda item: str(item.get("last_changed", "")))
    return rows[-limit:]


async def _ha_state_history(payload: dict[str, Any]) -> dict[str, Any]:
    entity_ids = _entity_ids_from_payload(payload)
    start, end = _history_window(payload, 24.0)
    limit = max(1, min(int(payload.get("limit", 200) or 200), 1000))
    query = {
        "filter_entity_id": ",".join(entity_ids),
        "end_time": end.isoformat(),
        "no_attributes": "0" if bool(payload.get("with_attributes", False)) else "1",
        "significant_changes_only": "0" if bool(payload.get("include_all_changes", True)) else "1",
    }
    if bool(payload.get("minimal_response", False)):
        query["minimal_response"] = "1"
    path = f"/api/history/period/{urllib.parse.quote(start.isoformat(), safe='')}?{urllib.parse.urlencode(query)}"
    raw = await _ha_request("GET", path)
    return {
        "entity_ids": entity_ids,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "limit": limit,
        "events": _simplify_history_rows(raw, limit),
    }


async def _ha_recent_changes(payload: dict[str, Any]) -> dict[str, Any]:
    start, end = _history_window(payload, 1.0)
    limit = max(1, min(int(payload.get("limit", 200) or 200), 1000))
    entity_ids_raw = payload.get("entity_ids", payload.get("entity_id", []))
    if isinstance(entity_ids_raw, str):
        entity_ids = [entity_ids_raw.strip()] if entity_ids_raw.strip() else []
    elif isinstance(entity_ids_raw, list):
        entity_ids = [str(item).strip() for item in entity_ids_raw if str(item).strip()]
    else:
        entity_ids = []
    query = {
        "end_time": end.isoformat(),
        "no_attributes": "1",
        "significant_changes_only": "0" if bool(payload.get("include_all_changes", True)) else "1",
    }
    if entity_ids:
        query["filter_entity_id"] = ",".join(entity_ids)
    path = f"/api/history/period/{urllib.parse.quote(start.isoformat(), safe='')}?{urllib.parse.urlencode(query)}"
    raw = await _ha_request("GET", path)
    return {
        "entity_ids": entity_ids,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "limit": limit,
        "events": _simplify_history_rows(raw, limit),
    }


async def _ha_logbook(payload: dict[str, Any]) -> dict[str, Any]:
    start, end = _history_window(payload, 24.0)
    limit = max(1, min(int(payload.get("limit", 200) or 200), 1000))
    entity_ids_raw = payload.get("entity_ids", payload.get("entity_id", []))
    if isinstance(entity_ids_raw, str):
        entity_ids = [entity_ids_raw.strip()] if entity_ids_raw.strip() else []
    elif isinstance(entity_ids_raw, list):
        entity_ids = [str(item).strip() for item in entity_ids_raw if str(item).strip()]
    else:
        entity_ids = []
    query = {"end_time": end.isoformat()}
    if entity_ids:
        query["entity"] = ",".join(entity_ids)
    path = f"/api/logbook/{urllib.parse.quote(start.isoformat(), safe='')}?{urllib.parse.urlencode(query)}"
    raw = await _ha_request("GET", path)
    entries = []
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict):
            continue
        entries.append(
            {
                "when": row.get("when", ""),
                "name": row.get("name", ""),
                "message": row.get("message", ""),
                "entity_id": row.get("entity_id", ""),
                "domain": row.get("domain", ""),
                "state": row.get("state", ""),
                "context_user_id": row.get("context_user_id", ""),
                "context_id": row.get("context_id", ""),
                "context_entity_id": row.get("context_entity_id", ""),
                "context_name": row.get("context_name", ""),
                "context_event_type": row.get("context_event_type", ""),
                "context_domain": row.get("context_domain", ""),
                "context_service": row.get("context_service", ""),
            }
        )
    entries.sort(key=lambda item: str(item.get("when", "")))
    return {
        "entity_ids": entity_ids,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "limit": limit,
        "entries": entries[-limit:],
    }


async def _ha_entity_report(payload: dict[str, Any]) -> dict[str, Any]:
    entity_id = str(payload.get("entity_id", "")).strip()
    if not entity_id:
        raise RuntimeError("Podaj entity_id.")
    hours = float(payload.get("hours", 168.0) or 168.0)
    limit = max(1, min(int(payload.get("limit", 50) or 50), 200))
    report: dict[str, Any] = {
        "entity_id": entity_id,
        "hours": hours,
        "current_state": await _ha_get_state({"entity_ids": [entity_id], "with_attributes": False}),
        "history": await _ha_state_history({"entity_ids": [entity_id], "hours": hours, "limit": limit}),
        "logbook": await _ha_logbook({"entity_ids": [entity_id], "hours": hours, "limit": limit}),
        "where_used": await _ha_where_used({"entity_id": entity_id}),
    }
    hints = []
    for entry in report.get("logbook", {}).get("entries", []):
        event_type = str(entry.get("context_event_type", "")).strip()
        if event_type:
            hints.append(
                {
                    "when": entry.get("when", ""),
                    "state": entry.get("state", ""),
                    "source": event_type,
                    "context_domain": entry.get("context_domain", ""),
                    "context_entity_id": entry.get("context_entity_id", ""),
                    "context_name": entry.get("context_name", ""),
                }
            )
    report["diagnostic_hints"] = hints[-limit:]
    return report


async def _ha_helper_list(payload: dict[str, Any]) -> dict[str, Any]:
    kind = str(payload.get("kind", "")).strip()
    states = await _ha_request("GET", "/api/states")
    helpers = []
    for row in states if isinstance(states, list) else []:
        entity_id = str(row.get("entity_id", "")).strip()
        domain = entity_id.split(".", 1)[0]
        if not domain.startswith("input_"):
            continue
        if kind and domain != kind:
            continue
        attrs = row.get("attributes", {}) if isinstance(row.get("attributes"), dict) else {}
        helpers.append(
            {
                "entity_id": entity_id,
                "state": row.get("state"),
                "friendly_name": attrs.get("friendly_name", ""),
            }
        )
    return {"helpers": helpers}


async def _ha_last_trigger(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload.get("target", payload.get("entity_id", ""))).strip()
    if not target:
        raise RuntimeError("Podaj target albo entity_id.")
    states = await _ha_request("GET", "/api/states")
    for row in states if isinstance(states, list) else []:
        entity_id = str(row.get("entity_id", "")).strip()
        if not entity_id.startswith("automation."):
            continue
        attrs = row.get("attributes", {}) if isinstance(row.get("attributes"), dict) else {}
        candidates = {entity_id, str(attrs.get("id", "")).strip(), str(attrs.get("friendly_name", "")).strip()}
        if target in candidates:
            return {
                "entity_id": entity_id,
                "state": row.get("state"),
                "id": attrs.get("id", ""),
                "friendly_name": attrs.get("friendly_name", ""),
                "last_triggered": attrs.get("last_triggered"),
                "mode": attrs.get("mode", ""),
            }
    raise RuntimeError(f"Nie znaleziono automatyzacji: {target}")


def _require_explicit_confirm(payload: dict[str, Any]) -> None:
    if str(payload.get("explicit_confirm", "")).strip() != "REQUIRED":
        raise RuntimeError("Ta operacja wymaga explicit_confirm=REQUIRED.")


class MutationLock:
    def __init__(self, label: str) -> None:
        self.label = label
        self.acquired = False

    def __enter__(self) -> "MutationLock":
        HA_EXPERT_NAMESPACE.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        if HA_EXPERT_MUTATION_LOCK.exists():
            age = now.timestamp() - HA_EXPERT_MUTATION_LOCK.stat().st_mtime
            if age > MUTATION_LOCK_STALE_SECONDS:
                HA_EXPERT_MUTATION_LOCK.unlink(missing_ok=True)
        try:
            fd = os.open(str(HA_EXPERT_MUTATION_LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            detail = HA_EXPERT_MUTATION_LOCK.read_text(encoding="utf-8", errors="replace").strip()
            raise RuntimeError(f"Inna mutacja YAML jest w toku. Lock: {detail}") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"label": self.label, "pid": os.getpid(), "created_at": now.isoformat()}, ensure_ascii=False))
        self.acquired = True
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.acquired:
            HA_EXPERT_MUTATION_LOCK.unlink(missing_ok=True)
            self.acquired = False


async def _ha_set_helper(payload: dict[str, Any]) -> dict[str, Any]:
    _require_explicit_confirm(payload)
    entity_id = str(payload.get("entity_id", "")).strip()
    value = payload.get("value")
    domain = entity_id.split(".", 1)[0] if "." in entity_id else ""
    if domain == "input_boolean":
        service = "turn_on" if str(value).lower() in {"1", "true", "on", "yes"} else "turn_off"
        data: dict[str, Any] = {"entity_id": entity_id}
    elif domain == "input_number":
        service = "set_value"
        data = {"entity_id": entity_id, "value": float(value)}
    elif domain == "input_text":
        service = "set_value"
        data = {"entity_id": entity_id, "value": "" if value is None else str(value)}
    elif domain == "input_select":
        service = "select_option"
        data = {"entity_id": entity_id, "option": "" if value is None else str(value)}
    else:
        raise RuntimeError("set-helper obsługuje tylko input_boolean, input_number, input_text i input_select.")
    result = await _ha_request("POST", f"/api/services/{domain}/{service}", data)
    return {"ok": True, "entity_id": entity_id, "service": f"{domain}.{service}", "result": result}


async def _ha_service_call(payload: dict[str, Any]) -> dict[str, Any]:
    _require_explicit_confirm(payload)
    domain = str(payload.get("domain", "")).strip()
    service = str(payload.get("service", "")).strip()
    if not domain or not service:
        raise RuntimeError("Podaj domain i service.")
    data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    body = dict(data)
    if "entity_id" in target and "entity_id" not in body:
        body["entity_id"] = target["entity_id"]
    result = await _ha_request("POST", f"/api/services/{domain}/{service}", body)
    return {"ok": True, "service": f"{domain}.{service}", "result": result}


async def _ha_ws_job(payload: dict[str, Any]) -> dict[str, Any]:
    _require_explicit_confirm(payload)
    message = payload.get("message", {}) if isinstance(payload.get("message"), dict) else {}
    if not message:
        message = {key: value for key, value in payload.items() if key not in {"explicit_confirm"}}
    if "type" not in message:
        raise RuntimeError("Podaj typ wiadomości WS.")
    return await _ha_ws_call(message)


def _file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.ha_expert_tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _tx_id(action: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_action = re.sub(r"[^a-z0-9_-]+", "-", action.lower()).strip("-") or "tx"
    return f"{stamp}-{safe_action}"


def _tx_manifest_path(tx_id: str) -> Path:
    safe_tx_id = re.sub(r"[^A-Za-z0-9_.-]+", "", tx_id)
    if not safe_tx_id or safe_tx_id != tx_id:
        raise RuntimeError("Niepoprawny tx_id.")
    return HA_EXPERT_TX_DIR / safe_tx_id / "manifest.json"


def _create_tx(action: str, files: list[Path], summary: dict[str, Any]) -> dict[str, Any]:
    HA_EXPERT_TX_DIR.mkdir(parents=True, exist_ok=True)
    txid = _tx_id(action)
    tx_dir = HA_EXPERT_TX_DIR / txid
    tx_dir.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, Any] = {
        "tx_id": txid,
        "action": action,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "files": [],
    }
    for path in files:
        backup_name = f"{path.name}.before"
        backup_path = tx_dir / backup_name
        if path.exists():
            shutil.copy2(path, backup_path)
        else:
            backup_path.write_text("", encoding="utf-8")
        manifest["files"].append(
            {
                "path": str(path),
                "backup": str(backup_path),
                "existed": path.exists(),
                "before_sha256": _file_sha256(path),
                "after_sha256": "",
            }
        )
    (tx_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def _finish_tx(manifest: dict[str, Any]) -> dict[str, Any]:
    for item in manifest.get("files", []):
        if isinstance(item, dict):
            item["after_sha256"] = _file_sha256(Path(str(item.get("path", ""))))
    manifest_path = _tx_manifest_path(str(manifest.get("tx_id", "")))
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def _tx_report(tx: dict[str, Any], action: str, reload_result: Any = None, check_result: Any = None) -> dict[str, Any]:
    tx_id = str(tx.get("tx_id", ""))
    return {
        "action": action,
        "tx_id": tx_id,
        "rollback_available": bool(tx_id),
        "rollback_job": {"kind": "ha_tx_rollback", "payload": {"tx_id": tx_id, "explicit_confirm": "REQUIRED"}} if tx_id else {},
        "files": tx.get("files", []),
        "reload": reload_result,
        "core_check": check_result,
    }


def _load_yaml(path: Path) -> Any:
    if not path.exists():
        return [] if path.name == "automations.yaml" else {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        data = yaml.safe_load(handle) or ([] if path.name == "automations.yaml" else {})
    return data


def _dump_yaml(data: Any) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)


AUTOMATION_KEY_ORDER = (
    "alias",
    "description",
    "triggers",
    "trigger",
    "conditions",
    "condition",
    "actions",
    "action",
    "mode",
    "max",
    "max_exceeded",
    "id",
)
SCRIPT_KEY_ORDER = (
    "alias",
    "description",
    "fields",
    "variables",
    "sequence",
    "mode",
    "max",
    "max_exceeded",
    "icon",
)


def _ordered_dict(source: dict[str, Any], preferred_order: tuple[str, ...]) -> dict[str, Any]:
    ordered: dict[str, Any] = {}
    for key in preferred_order:
        if key in source:
            ordered[key] = source[key]
    for key, value in source.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def _normalize_automation_style(item: dict[str, Any]) -> dict[str, Any]:
    return _ordered_dict(item, AUTOMATION_KEY_ORDER)


def _normalize_script_style(item: dict[str, Any]) -> dict[str, Any]:
    return _ordered_dict(item, SCRIPT_KEY_ORDER)


def _style_info(item: dict[str, Any], expected_first: str = "alias") -> dict[str, Any]:
    keys = list(item.keys())
    return {
        "first_key": keys[0] if keys else "",
        "expected_first_key": expected_first,
        "first_key_ok": bool(keys and keys[0] == expected_first),
        "key_order": keys,
    }


def _parse_payload_yaml(payload: dict[str, Any]) -> Any:
    raw = payload.get("yaml", "")
    if isinstance(raw, (dict, list)):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError("Podaj YAML w polu yaml.")
    try:
        return yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Niepoprawny YAML: {exc}") from exc


def _single_automation_from_yaml(data: Any) -> dict[str, Any]:
    if isinstance(data, list):
        if len(data) != 1:
            raise RuntimeError("YAML automatyzacji musi zawierać dokładnie jedną automatyzację.")
        data = data[0]
    if not isinstance(data, dict):
        raise RuntimeError("Automatyzacja musi być obiektem YAML.")
    alias = str(data.get("alias", "")).strip()
    if not alias:
        raise RuntimeError("Automatyzacja musi mieć alias.")
    if "trigger" not in data and "triggers" not in data:
        raise RuntimeError("Automatyzacja musi mieć trigger albo triggers.")
    if "action" not in data and "actions" not in data:
        raise RuntimeError("Automatyzacja musi mieć action albo actions.")
    return _normalize_automation_style(data)


def _single_script_from_yaml(data: Any, explicit_key: str = "") -> tuple[str, dict[str, Any]]:
    explicit_key = explicit_key.strip()
    if isinstance(data, dict) and len(data) == 1 and not {"alias", "sequence", "mode", "fields"} & set(data.keys()):
        key, item = next(iter(data.items()))
        if not isinstance(item, dict):
            raise RuntimeError("Skrypt musi być obiektem YAML.")
        script_key = explicit_key or str(key).strip()
        script = item
    elif isinstance(data, dict):
        script_key = explicit_key
        script = data
    else:
        raise RuntimeError("YAML skryptu musi być mapą {key: script} albo obiektem skryptu.")
    if not script_key:
        raise RuntimeError("Podaj key skryptu albo YAML w formacie {key: script}.")
    if "sequence" not in script:
        raise RuntimeError("Skrypt musi mieć sequence.")
    return script_key, _normalize_script_style(script)


def _validate_yaml_payload(payload: dict[str, Any]) -> dict[str, Any]:
    target_type = str(payload.get("target_type", payload.get("type", ""))).strip()
    data = _parse_payload_yaml(payload)
    if target_type in {"automation", "automations"}:
        item = _single_automation_from_yaml(data)
        return {
            "ok": True,
            "target_type": "automation",
            "alias": str(item.get("alias", "")),
            "id": str(item.get("id", "")),
            "style": _style_info(item),
            "normalized_yaml": _dump_yaml([item]),
        }
    if target_type in {"script", "scripts"}:
        key, item = _single_script_from_yaml(data, str(payload.get("key", "")))
        return {
            "ok": True,
            "target_type": "script",
            "key": key,
            "alias": str(item.get("alias", "")),
            "style": _style_info(item),
            "normalized_yaml": _dump_yaml({key: item}),
        }
    raise RuntimeError("target_type musi mieć wartość automation albo script.")


def _automation_entity_id(item: dict[str, Any]) -> str:
    alias = str(item.get("alias", "")).strip().lower()
    slug = re.sub(r"[^a-z0-9_]+", "_", alias.replace(" ", "_")).strip("_")
    slug = re.sub(r"_+", "_", slug)
    return f"automation.{slug}" if slug else ""


def _walk(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    out = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            out.extend(_walk(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            out.extend(_walk(child, f"{path}[{idx}]"))
    return out


def _usage_kind(path: str) -> str:
    lowered = path.lower()
    if ".trigger" in lowered or ".triggers" in lowered:
        return "trigger"
    if ".condition" in lowered or ".conditions" in lowered:
        return "condition"
    if ".action" in lowered or ".actions" in lowered or ".sequence" in lowered:
        return "action"
    return "reference"


def _value_contains(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value) == needle
    if isinstance(value, list):
        return any(_value_contains(item, needle) for item in value)
    if isinstance(value, dict):
        return any(_value_contains(item, needle) for item in value.values())
    return False


def _matches_text(data: Any, query: str) -> bool:
    return query.lower() in _dump_yaml(data).lower()


def _automation_matches(item: dict[str, Any], target: str, match_by: str) -> bool:
    target = target.strip()
    if match_by == "id":
        return str(item.get("id", "")).strip() == target
    if match_by == "entity_id":
        return _automation_entity_id(item) == target
    return str(item.get("alias", "")).strip() == target


def _script_matches(key: str, item: dict[str, Any], target: str, match_by: str) -> bool:
    target = target.strip()
    if match_by == "key":
        return key == target
    return str(item.get("alias", "")).strip() == target


async def _ha_scan(payload: dict[str, Any]) -> dict[str, Any]:
    compact = bool(payload.get("compact", True))
    automations = _load_yaml(AUTOMATIONS_FILE)
    scripts = _load_yaml(SCRIPTS_FILE)
    auto_items = automations if isinstance(automations, list) else []
    script_items = scripts if isinstance(scripts, dict) else {}
    result: dict[str, Any] = {
        "files": {
            "automations": str(AUTOMATIONS_FILE),
            "scripts": str(SCRIPTS_FILE),
        },
        "counts": {
            "automations": len(auto_items),
            "scripts": len(script_items),
        },
    }
    if not compact:
        result["automations"] = [
            {"id": str(item.get("id", "")), "alias": str(item.get("alias", ""))}
            for item in auto_items
            if isinstance(item, dict)
        ]
        result["scripts"] = [
            {"key": key, "alias": str(item.get("alias", ""))}
            for key, item in script_items.items()
            if isinstance(item, dict)
        ]
    return result


async def _ha_find(payload: dict[str, Any]) -> dict[str, Any]:
    query = str(payload.get("query", "")).strip()
    if not query:
        raise RuntimeError("Podaj query.")
    query_l = query.lower()
    automations = _load_yaml(AUTOMATIONS_FILE)
    scripts = _load_yaml(SCRIPTS_FILE)
    found_autos = []
    for item in automations if isinstance(automations, list) else []:
        if isinstance(item, dict) and _matches_text(item, query_l):
            found_autos.append({"id": str(item.get("id", "")), "alias": str(item.get("alias", ""))})
    found_scripts = []
    for key, item in scripts.items() if isinstance(scripts, dict) else []:
        if isinstance(item, dict) and _matches_text(item, query_l):
            found_scripts.append({"key": key, "alias": str(item.get("alias", ""))})
    return {"query": query, "automations": found_autos, "scripts": found_scripts}


async def _ha_where_used(payload: dict[str, Any]) -> dict[str, Any]:
    entity_id = str(payload.get("entity_id", "")).strip()
    if not entity_id:
        raise RuntimeError("Podaj entity_id.")
    automations = _load_yaml(AUTOMATIONS_FILE)
    scripts = _load_yaml(SCRIPTS_FILE)
    found_autos = []
    for item in automations if isinstance(automations, list) else []:
        if not isinstance(item, dict):
            continue
        occurrences = []
        kinds: set[str] = set()
        for path, value in _walk(item):
            if isinstance(value, (dict, list)):
                continue
            if _value_contains(value, entity_id):
                kind = _usage_kind(path)
                kinds.add(kind)
                occurrences.append({"path": path, "usage_kind": kind, "snippet": str(value)[:220]})
        if occurrences:
            found_autos.append(
                {
                    "id": str(item.get("id", "")),
                    "alias": str(item.get("alias", "")),
                    "usage_kinds": sorted(kinds),
                    "occurrence_count": len(occurrences),
                    "occurrences": occurrences,
                }
            )
    found_scripts = []
    for key, item in scripts.items() if isinstance(scripts, dict) else []:
        if not isinstance(item, dict):
            continue
        occurrences = []
        kinds: set[str] = set()
        for path, value in _walk(item):
            if isinstance(value, (dict, list)):
                continue
            if _value_contains(value, entity_id):
                kind = _usage_kind(path)
                kinds.add(kind)
                occurrences.append({"path": path, "usage_kind": kind, "snippet": str(value)[:220]})
        if occurrences:
            found_scripts.append(
                {
                    "key": key,
                    "alias": str(item.get("alias", "")),
                    "usage_kinds": sorted(kinds),
                    "occurrence_count": len(occurrences),
                    "occurrences": occurrences,
                }
            )
    return {
        "entity_id": entity_id,
        "automations": found_autos,
        "scripts": found_scripts,
        "summary": {"automations": len(found_autos), "scripts": len(found_scripts)},
    }


async def _ha_get_automation(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload.get("target", "")).strip()
    match_by = str(payload.get("match_by", "alias")).strip() or "alias"
    if not target:
        raise RuntimeError("Podaj target.")
    automations = _load_yaml(AUTOMATIONS_FILE)
    for item in automations if isinstance(automations, list) else []:
        if isinstance(item, dict) and _automation_matches(item, target, match_by):
            return {
                "id": str(item.get("id", "")),
                "alias": str(item.get("alias", "")),
                "enabled": "enabled_or_default",
                "yaml": _dump_yaml([item]),
            }
    raise RuntimeError(f"Nie znaleziono automatyzacji: {target}")


async def _ha_get_script(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload.get("target", "")).strip()
    match_by = str(payload.get("match_by", "alias")).strip() or "alias"
    if not target:
        raise RuntimeError("Podaj target.")
    scripts = _load_yaml(SCRIPTS_FILE)
    for key, item in scripts.items() if isinstance(scripts, dict) else []:
        if isinstance(item, dict) and _script_matches(key, item, target, match_by):
            return {"key": key, "alias": str(item.get("alias", "")), "yaml": _dump_yaml({key: item})}
    raise RuntimeError(f"Nie znaleziono skryptu: {target}")


async def _ha_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    topic = str(payload.get("topic", "")).strip()
    if not topic:
        raise RuntimeError("Podaj topic.")
    found = await _ha_find({"query": topic})
    automations = []
    for item in found["automations"]:
        try:
            automations.append(await _ha_get_automation({"target": item["id"], "match_by": "id"}))
        except Exception:
            pass
    scripts = []
    for item in found["scripts"]:
        try:
            scripts.append(await _ha_get_script({"target": item["key"], "match_by": "key"}))
        except Exception:
            pass
    return {"topic": topic, "automations": automations, "scripts": scripts}


def _preview_diff(path: Path, new_text: str, limit: int = 240) -> dict[str, Any]:
    old_text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    diff_lines = list(
        difflib.unified_diff(
            old_text.splitlines(),
            new_text.splitlines(),
            fromfile=str(path),
            tofile=f"{path} (new)",
            lineterm="",
        )
    )
    truncated = len(diff_lines) > limit
    return {"changed": old_text != new_text, "truncated": truncated, "diff": "\n".join(diff_lines[:limit])}


def _append_yaml_block(path: Path, block: str) -> str:
    old_text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    prefix = old_text.rstrip()
    return f"{prefix}\n{block.strip()}\n" if prefix else f"{block.strip()}\n"


def _replace_top_level_sequence_block(path: Path, index: int, block: str) -> str:
    old_text = path.read_text(encoding="utf-8", errors="replace")
    lines = old_text.splitlines(keepends=True)
    starts = [idx for idx, line in enumerate(lines) if line.startswith("- ")]
    if index < 0 or index >= len(starts):
        raise RuntimeError("Nie udało się bezpiecznie wyznaczyć bloku automatyzacji w YAML.")
    start = starts[index]
    end = starts[index + 1] if index + 1 < len(starts) else len(lines)
    return "".join(lines[:start]) + block.strip() + "\n" + "".join(lines[end:])


def _delete_top_level_sequence_block(path: Path, index: int) -> str:
    old_text = path.read_text(encoding="utf-8", errors="replace")
    lines = old_text.splitlines(keepends=True)
    starts = [idx for idx, line in enumerate(lines) if line.startswith("- ")]
    if index < 0 or index >= len(starts):
        raise RuntimeError("Nie udało się bezpiecznie wyznaczyć bloku automatyzacji w YAML.")
    start = starts[index]
    end = starts[index + 1] if index + 1 < len(starts) else len(lines)
    return "".join(lines[:start]) + "".join(lines[end:])


def _mapping_key_pattern(key: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(key)}:\s*(?:#.*)?$")


def _replace_top_level_mapping_block(path: Path, key: str, block: str) -> str:
    old_text = path.read_text(encoding="utf-8", errors="replace")
    lines = old_text.splitlines(keepends=True)
    pattern = _mapping_key_pattern(key)
    starts = [idx for idx, line in enumerate(lines) if pattern.match(line.rstrip("\n\r"))]
    if len(starts) != 1:
        raise RuntimeError(f"Nie udało się bezpiecznie wyznaczyć bloku skryptu: {key}")
    start = starts[0]
    end = len(lines)
    for idx in range(start + 1, len(lines)):
        line = lines[idx]
        if line and not line.startswith((" ", "\t", "#", "\n", "\r")) and re.match(r"^[A-Za-z0-9_][A-Za-z0-9_-]*:\s*", line):
            end = idx
            break
    return "".join(lines[:start]) + block.strip() + "\n" + "".join(lines[end:])


def _delete_top_level_mapping_block(path: Path, key: str) -> str:
    return _replace_top_level_mapping_block(path, key, "")


def _find_automation_index(items: list[Any], target: str, match_by: str, new_item: dict[str, Any] | None = None) -> int | None:
    target = target.strip()
    if not target and new_item is not None:
        if match_by == "id":
            target = str(new_item.get("id", "")).strip()
        elif match_by == "entity_id":
            target = _automation_entity_id(new_item)
        else:
            target = str(new_item.get("alias", "")).strip()
    for idx, item in enumerate(items):
        if isinstance(item, dict) and _automation_matches(item, target, match_by):
            return idx
    return None


async def _reload_yaml_domain(domain: str) -> dict[str, Any]:
    if domain not in {"automation", "script"}:
        raise RuntimeError("Niepoprawna domena reload.")
    result = await _ha_request("POST", f"/api/services/{domain}/reload", {})
    return {"service": f"{domain}.reload", "result": result}


async def _post_mutation_checks(domain: str, payload: dict[str, Any]) -> tuple[Any, Any]:
    reload_result = None
    check_result = None
    if bool(payload.get("reload", True)):
        reload_result = await _reload_yaml_domain(domain)
    if bool(payload.get("core_check", True)):
        check_result = await _ha_core_check({})
    return reload_result, check_result


async def _ha_validate_yaml(payload: dict[str, Any]) -> dict[str, Any]:
    return _validate_yaml_payload(payload)


def _entity_target(entity_id: str) -> dict[str, Any]:
    entity_id = entity_id.strip()
    return {"entity_id": entity_id} if entity_id else {}


def _service_action(service: str, target_entity: str = "", data: dict[str, Any] | None = None) -> dict[str, Any]:
    action: dict[str, Any] = {"service": service.strip()}
    target = _entity_target(target_entity)
    if target:
        action["target"] = target
    if data:
        action["data"] = data
    return action


async def _ha_generate_automation(payload: dict[str, Any]) -> dict[str, Any]:
    template = str(payload.get("template", "state-service")).strip() or "state-service"
    alias = str(payload.get("alias", "")).strip()
    if not alias:
        raise RuntimeError("Podaj alias automatyzacji.")
    description = str(payload.get("description", "")).strip()
    mode = str(payload.get("mode", "single")).strip() or "single"
    service = str(payload.get("service", "")).strip()
    target_entity = str(payload.get("target_entity", "")).strip()
    data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    generated_id = str(payload.get("id", "")).strip()
    item: dict[str, Any] = {"alias": alias}
    if description:
        item["description"] = description
    if template in {"state-service", "state-script"}:
        trigger_entity = str(payload.get("trigger_entity", "")).strip()
        if not trigger_entity:
            raise RuntimeError("Dla state-service/state-script podaj trigger_entity.")
        trigger: dict[str, Any] = {"platform": "state", "entity_id": trigger_entity}
        to_state = str(payload.get("to_state", "")).strip()
        from_state = str(payload.get("from_state", "")).strip()
        if from_state:
            trigger["from"] = from_state
        if to_state:
            trigger["to"] = to_state
        item["trigger"] = [trigger]
    elif template == "time-service":
        at = str(payload.get("at", "")).strip()
        if not at:
            raise RuntimeError("Dla time-service podaj at, np. 07:30:00.")
        item["trigger"] = [{"platform": "time", "at": at}]
    else:
        raise RuntimeError("Nieznany template automatyzacji.")
    if template == "state-script":
        script_entity = str(payload.get("script_entity", payload.get("script", ""))).strip()
        if not script_entity:
            raise RuntimeError("Dla state-script podaj script_entity.")
        service = "script.turn_on"
        target_entity = script_entity
    if not service:
        raise RuntimeError("Podaj service akcji.")
    item["action"] = [_service_action(service, target_entity, data)]
    item["mode"] = mode
    if generated_id:
        item["id"] = generated_id
    normalized = _single_automation_from_yaml(item)
    return {
        "ok": True,
        "target_type": "automation",
        "template": template,
        "alias": alias,
        "style": _style_info(normalized),
        "yaml": _dump_yaml([normalized]),
    }


async def _ha_generate_script(payload: dict[str, Any]) -> dict[str, Any]:
    key = str(payload.get("key", "")).strip()
    alias = str(payload.get("alias", "")).strip()
    service = str(payload.get("service", "")).strip()
    target_entity = str(payload.get("target_entity", "")).strip()
    data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    mode = str(payload.get("mode", "single")).strip() or "single"
    if not key:
        raise RuntimeError("Podaj key skryptu.")
    if not alias:
        raise RuntimeError("Podaj alias skryptu.")
    if not service:
        raise RuntimeError("Podaj service skryptu.")
    script = _normalize_script_style({"alias": alias, "sequence": [_service_action(service, target_entity, data)], "mode": mode})
    return {
        "ok": True,
        "target_type": "script",
        "key": key,
        "alias": alias,
        "style": _style_info(script),
        "yaml": _dump_yaml({key: script}),
    }


async def _ha_upsert_automation(payload: dict[str, Any]) -> dict[str, Any]:
    dry_run = bool(payload.get("dry_run", False))
    if not dry_run:
        _require_explicit_confirm(payload)
    match_by = str(payload.get("match_by", "id")).strip() or "id"
    if match_by not in {"alias", "id", "entity_id"}:
        raise RuntimeError("match_by dla automatyzacji: alias, id albo entity_id.")
    target = str(payload.get("target", "")).strip()
    new_item = _single_automation_from_yaml(_parse_payload_yaml(payload))
    automations = _load_yaml(AUTOMATIONS_FILE)
    if not isinstance(automations, list):
        raise RuntimeError("automations.yaml nie jest listą.")
    idx = _find_automation_index(automations, target, match_by, new_item)
    action = "replace" if idx is not None else "append"
    block = _dump_yaml([new_item])
    if idx is None:
        new_text = _append_yaml_block(AUTOMATIONS_FILE, block)
    else:
        new_text = _replace_top_level_sequence_block(AUTOMATIONS_FILE, idx, block)
    preview = _preview_diff(AUTOMATIONS_FILE, new_text)
    result: dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "file": str(AUTOMATIONS_FILE),
        "action": action,
        "index": idx,
        "alias": str(new_item.get("alias", "")),
        "id": str(new_item.get("id", "")),
        "preview": preview,
    }
    if dry_run:
        return result
    with MutationLock("upsert-automation"):
        tx = _create_tx("upsert-automation", [AUTOMATIONS_FILE], {"action": action, "alias": result["alias"], "id": result["id"]})
        _atomic_write_text(AUTOMATIONS_FILE, new_text)
        result["tx"] = _finish_tx(tx)
        reload_result, check_result = await _post_mutation_checks("automation", payload)
    result["reload"] = reload_result
    result["core_check"] = check_result
    result["report"] = _tx_report(result["tx"], "upsert-automation", reload_result, check_result)
    return result


async def _ha_delete_automation(payload: dict[str, Any]) -> dict[str, Any]:
    dry_run = bool(payload.get("dry_run", False))
    if not dry_run:
        _require_explicit_confirm(payload)
    target = str(payload.get("target", "")).strip()
    match_by = str(payload.get("match_by", "alias")).strip() or "alias"
    if not target:
        raise RuntimeError("Podaj target automatyzacji.")
    automations = _load_yaml(AUTOMATIONS_FILE)
    if not isinstance(automations, list):
        raise RuntimeError("automations.yaml nie jest listą.")
    idx = _find_automation_index(automations, target, match_by)
    if idx is None:
        raise RuntimeError(f"Nie znaleziono automatyzacji: {target}")
    removed = automations[idx]
    new_text = _delete_top_level_sequence_block(AUTOMATIONS_FILE, idx)
    result: dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "file": str(AUTOMATIONS_FILE),
        "action": "delete",
        "index": idx,
        "removed": {"id": str(removed.get("id", "")), "alias": str(removed.get("alias", ""))} if isinstance(removed, dict) else {},
        "preview": _preview_diff(AUTOMATIONS_FILE, new_text),
    }
    if dry_run:
        return result
    with MutationLock("delete-automation"):
        tx = _create_tx("delete-automation", [AUTOMATIONS_FILE], result["removed"])
        _atomic_write_text(AUTOMATIONS_FILE, new_text)
        result["tx"] = _finish_tx(tx)
        reload_result, check_result = await _post_mutation_checks("automation", payload)
    result["reload"] = reload_result
    result["core_check"] = check_result
    result["report"] = _tx_report(result["tx"], "delete-automation", reload_result, check_result)
    return result


async def _ha_upsert_script(payload: dict[str, Any]) -> dict[str, Any]:
    dry_run = bool(payload.get("dry_run", False))
    if not dry_run:
        _require_explicit_confirm(payload)
    key, script = _single_script_from_yaml(_parse_payload_yaml(payload), str(payload.get("key", "")))
    scripts = _load_yaml(SCRIPTS_FILE)
    if not isinstance(scripts, dict):
        raise RuntimeError("scripts.yaml nie jest mapą.")
    action = "replace" if key in scripts else "append"
    block = _dump_yaml({key: script})
    if action == "append":
        new_text = _append_yaml_block(SCRIPTS_FILE, block)
    else:
        new_text = _replace_top_level_mapping_block(SCRIPTS_FILE, key, block)
    result: dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "file": str(SCRIPTS_FILE),
        "action": action,
        "key": key,
        "alias": str(script.get("alias", "")),
        "preview": _preview_diff(SCRIPTS_FILE, new_text),
    }
    if dry_run:
        return result
    with MutationLock("upsert-script"):
        tx = _create_tx("upsert-script", [SCRIPTS_FILE], {"action": action, "key": key, "alias": result["alias"]})
        _atomic_write_text(SCRIPTS_FILE, new_text)
        result["tx"] = _finish_tx(tx)
        reload_result, check_result = await _post_mutation_checks("script", payload)
    result["reload"] = reload_result
    result["core_check"] = check_result
    result["report"] = _tx_report(result["tx"], "upsert-script", reload_result, check_result)
    return result


async def _ha_delete_script(payload: dict[str, Any]) -> dict[str, Any]:
    dry_run = bool(payload.get("dry_run", False))
    if not dry_run:
        _require_explicit_confirm(payload)
    key = str(payload.get("key", payload.get("target", ""))).strip()
    if not key:
        raise RuntimeError("Podaj key skryptu.")
    scripts = _load_yaml(SCRIPTS_FILE)
    if not isinstance(scripts, dict):
        raise RuntimeError("scripts.yaml nie jest mapą.")
    if key not in scripts:
        raise RuntimeError(f"Nie znaleziono skryptu: {key}")
    removed = scripts[key]
    new_text = _delete_top_level_mapping_block(SCRIPTS_FILE, key)
    result: dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "file": str(SCRIPTS_FILE),
        "action": "delete",
        "key": key,
        "removed": {"alias": str(removed.get("alias", ""))} if isinstance(removed, dict) else {},
        "preview": _preview_diff(SCRIPTS_FILE, new_text),
    }
    if dry_run:
        return result
    with MutationLock("delete-script"):
        tx = _create_tx("delete-script", [SCRIPTS_FILE], {"key": key, **result["removed"]})
        _atomic_write_text(SCRIPTS_FILE, new_text)
        result["tx"] = _finish_tx(tx)
        reload_result, check_result = await _post_mutation_checks("script", payload)
    result["reload"] = reload_result
    result["core_check"] = check_result
    result["report"] = _tx_report(result["tx"], "delete-script", reload_result, check_result)
    return result


async def _ha_tx_list(payload: dict[str, Any]) -> dict[str, Any]:
    limit = max(1, min(int(payload.get("limit", 20) or 20), 200))
    rows = []
    for manifest_path in sorted(HA_EXPERT_TX_DIR.glob("*/manifest.json"), reverse=True) if HA_EXPERT_TX_DIR.exists() else []:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append(
            {
                "tx_id": manifest.get("tx_id", ""),
                "action": manifest.get("action", ""),
                "created_at": manifest.get("created_at", ""),
                "summary": manifest.get("summary", {}),
                "files": [
                    {"path": item.get("path", ""), "before_sha256": item.get("before_sha256", ""), "after_sha256": item.get("after_sha256", "")}
                    for item in manifest.get("files", [])
                    if isinstance(item, dict)
                ],
            }
        )
    return {"transactions": rows[:limit]}


async def _ha_tx_rollback(payload: dict[str, Any]) -> dict[str, Any]:
    _require_explicit_confirm(payload)
    txid = str(payload.get("tx_id", "")).strip()
    if not txid:
        raise RuntimeError("Podaj tx_id.")
    manifest_path = _tx_manifest_path(txid)
    if not manifest_path.exists():
        raise RuntimeError(f"Nie znaleziono transakcji: {txid}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    with MutationLock("rollback"):
        rollback_tx = _create_tx("rollback", [Path(str(item.get("path", ""))) for item in manifest.get("files", []) if isinstance(item, dict)], {"rollback_of": txid})
        restored = []
        reload_domains: set[str] = set()
        for item in manifest.get("files", []):
            if not isinstance(item, dict):
                continue
            path = Path(str(item.get("path", "")))
            backup = Path(str(item.get("backup", "")))
            if not backup.exists():
                raise RuntimeError(f"Brak backupu dla {path}.")
            _atomic_write_text(path, backup.read_text(encoding="utf-8", errors="replace"))
            restored.append(str(path))
            if path == AUTOMATIONS_FILE:
                reload_domains.add("automation")
            if path == SCRIPTS_FILE:
                reload_domains.add("script")
        result: dict[str, Any] = {"ok": True, "rollback_of": txid, "restored": restored, "tx": _finish_tx(rollback_tx)}
        reload_result = []
        if bool(payload.get("reload", True)):
            reload_result = [await _reload_yaml_domain(domain) for domain in sorted(reload_domains)]
        check_result = await _ha_core_check({}) if bool(payload.get("core_check", True)) else None
    result["reload"] = reload_result
    result["core_check"] = check_result
    result["report"] = _tx_report(result["tx"], "rollback", reload_result, check_result)
    return result


async def _run_operator_job(job: dict[str, Any]) -> None:
    job_id = str(job.get("job_id", "")).strip()
    kind = str(job.get("kind", "")).strip()
    payload = job.get("payload", {}) if isinstance(job.get("payload"), dict) else {}
    if not job_id:
        return

    try:
        if kind == "ha_log_tail":
            result = _read_ha_log_tail(
                int(payload.get("lines", DEFAULT_HA_LOG_LINES) or DEFAULT_HA_LOG_LINES),
                str(payload.get("severity", "all")),
            )
        elif kind == "client_capabilities":
            result = _client_capabilities()
        elif kind == "ha_entity_report":
            result = await _ha_entity_report(payload)
        elif kind == "ha_validate_yaml":
            result = await _ha_validate_yaml(payload)
        elif kind == "ha_generate_automation":
            result = await _ha_generate_automation(payload)
        elif kind == "ha_generate_script":
            result = await _ha_generate_script(payload)
        elif kind == "ha_core_check":
            result = await _ha_core_check(payload)
        elif kind == "ha_test_auth":
            result = await _ha_test_auth()
        elif kind == "ha_get_state":
            result = await _ha_get_state(payload)
        elif kind == "ha_state_history":
            result = await _ha_state_history(payload)
        elif kind == "ha_recent_changes":
            result = await _ha_recent_changes(payload)
        elif kind == "ha_helper_list":
            result = await _ha_helper_list(payload)
        elif kind == "ha_scan":
            result = await _ha_scan(payload)
        elif kind == "ha_find":
            result = await _ha_find(payload)
        elif kind == "ha_where_used":
            result = await _ha_where_used(payload)
        elif kind == "ha_get_automation":
            result = await _ha_get_automation(payload)
        elif kind == "ha_get_script":
            result = await _ha_get_script(payload)
        elif kind == "ha_snapshot":
            result = await _ha_snapshot(payload)
        elif kind == "ha_upsert_automation":
            result = await _ha_upsert_automation(payload)
        elif kind == "ha_delete_automation":
            result = await _ha_delete_automation(payload)
        elif kind == "ha_upsert_script":
            result = await _ha_upsert_script(payload)
        elif kind == "ha_delete_script":
            result = await _ha_delete_script(payload)
        elif kind == "ha_tx_list":
            result = await _ha_tx_list(payload)
        elif kind == "ha_tx_rollback":
            result = await _ha_tx_rollback(payload)
        elif kind == "ha_last_trigger":
            result = await _ha_last_trigger(payload)
        elif kind == "ha_logbook":
            result = await _ha_logbook(payload)
        elif kind == "ha_set_helper":
            result = await _ha_set_helper(payload)
        elif kind == "ha_service_call":
            result = await _ha_service_call(payload)
        elif kind == "ha_ws_call":
            result = await _ha_ws_job(payload)
        else:
            raise RuntimeError(f"Nieznany typ zadania: {kind}")
        await _operator_post("/api/v1/jobs/result", {"job_id": job_id, "ok": True, "result": result})
    except Exception as exc:
        await _operator_post(
            "/api/v1/jobs/result",
            {"job_id": job_id, "ok": False, "error": str(exc).strip() or "Nie udało się wykonać zadania."},
        )


def _is_tailscale_host(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    if host.endswith(".ts.net"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return ip in ipaddress.ip_network("100.64.0.0/10")
    return ip in ipaddress.ip_network("fd7a:115c:a1e0::/48")


def _post_via_tailscale_nc(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    parsed = urlparse(OPERATOR_URL)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    body = json.dumps(payload, ensure_ascii=False)
    request_path = path if path.startswith("/") else f"/{path}"
    request_text = (
        f"POST {request_path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n"
        f"{body}"
    )
    proc = subprocess.run(
        [
            "tailscale",
            "--socket",
            TAILSCALE_SOCKET,
            "nc",
            host,
            str(port),
        ],
        input=request_text,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or proc.stdout.strip() or "Nie udało się połączyć z operatorem przez Tailscale."
        raise web.HTTPBadGateway(text=stderr)

    raw = proc.stdout
    if "\r\n\r\n" in raw:
        head, body_text = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body_text = raw.split("\n\n", 1)
    else:
        raise web.HTTPBadGateway(text="Operator zwrócił nieprawidłową odpowiedź.")

    status_line = head.splitlines()[0] if head.splitlines() else ""
    match = re.match(r"HTTP/\d+(?:\.\d+)?\s+(\d+)", status_line)
    status_code = int(match.group(1)) if match else 502
    try:
        data = json.loads(body_text.strip() or "{}")
    except json.JSONDecodeError:
        data = {}

    if status_code >= 400:
        message = str(data.get("error", "Operator odrzucił żądanie.")).strip() if isinstance(data, dict) else "Operator odrzucił żądanie."
        raise web.HTTPBadGateway(text=message)
    return data if isinstance(data, dict) else {}


async def _operator_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    parsed = urlparse(OPERATOR_URL)
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        kwargs: dict[str, Any] = {"json": payload}
        if _is_tailscale_host(parsed.hostname or ""):
            kwargs["proxy"] = TAILSCALE_HTTP_PROXY
        async with session.post(f"{OPERATOR_URL}{path}", **kwargs) as response:
            data = await response.json(content_type=None)
            if response.status >= 400:
                message = str(data.get("error", "Operator odrzucił żądanie.")).strip() if isinstance(data, dict) else "Operator odrzucił żądanie."
                raise web.HTTPBadGateway(text=message)
            return data


async def index(_: web.Request) -> web.Response:
    return web.FileResponse(STATIC_DIR / "index.html")


async def status(_: web.Request) -> web.Response:
    state = _read_state()
    payload = {
        "ok": True,
        "client_login": state.get("client_login", "") or CONFIGURED_CLIENT_LOGIN,
        "connected": bool(state.get("connected", False)),
        "last_error": state.get("last_error", ""),
        "last_notice": state.get("last_notice", ""),
        "configured": bool(CONFIGURED_CLIENT_LOGIN and CONFIGURED_HA_TOKEN),
    }
    return web.json_response(payload, dumps=lambda x: json.dumps(x, ensure_ascii=False))


async def capabilities(_: web.Request) -> web.Response:
    return web.json_response({"ok": True, "capabilities": _client_capabilities()}, dumps=lambda x: json.dumps(x, ensure_ascii=False))


async def connect(request: web.Request) -> web.Response:
    client_login = CONFIGURED_CLIENT_LOGIN
    ha_token = CONFIGURED_HA_TOKEN

    if not client_login:
        return web.json_response({"ok": False, "error": "Najpierw wpisz login klienta w ustawieniach dodatku."}, status=400)
    if not ha_token:
        return web.json_response({"ok": False, "error": "Najpierw wpisz token Live w ustawieniach dodatku."}, status=400)

    state = _read_state()
    tailscale: TailscaleAdapter = request.app["tailscale"]
    try:
        tailscale_info = await tailscale.connect(client_login)
        await request.app["ha_relay"].start()
        tailscale.reset_serve()
    except Exception as exc:
        state["client_login"] = client_login
        state["ha_token"] = ha_token
        state["connected"] = False
        state["dashboard_url"] = ""
        state["last_error"] = str(exc).strip() or "Nie udało się połączyć z Tailscale."
        state["last_notice"] = ""
        _write_state(state)
        return web.json_response({"ok": False, "error": state["last_error"]}, status=502)

    state.update(
        {
            "client_login": client_login,
            "ha_token": ha_token,
            "connected": tailscale_info.get("connected") == "true",
            "tailscale_ip": tailscale_info.get("tailscale_ip", ""),
            "tailscale_node": tailscale_info.get("tailscale_node", ""),
            "dashboard_url": _build_dashboard_url(tailscale_info.get("tailscale_ip", "")),
            "last_error": "",
            "last_notice": tailscale.last_connect_warning,
        }
    )
    _write_state(state)

    operator_payload = {
        "client_login": client_login,
        "ha_url": INTERNAL_HA_URL,
        "ha_port": INTERNAL_HA_PORT,
        "tailscale_ip": state.get("tailscale_ip", ""),
        "tailscale_node": state.get("tailscale_node", ""),
        "dashboard_url": state.get("dashboard_url", ""),
    }
    try:
        await _operator_post("/api/v1/connect", operator_payload)
    except web.HTTPException as exc:
        state["connected"] = False
        state["tailscale_ip"] = ""
        state["tailscale_node"] = ""
        state["dashboard_url"] = ""
        state["last_error"] = exc.text or "Nie udało się zarejestrować połączenia."
        _write_state(state)
        await request.app["ha_relay"].stop()
        await tailscale.disconnect()
        return web.json_response({"ok": False, "error": state["last_error"]}, status=502)

    runtime: dict[str, Any] = request.app["runtime"]
    heartbeat_task: asyncio.Task | None = runtime.get("heartbeat_task")
    if heartbeat_task and not heartbeat_task.done():
        heartbeat_task.cancel()
    runtime["heartbeat_task"] = asyncio.create_task(_heartbeat_loop(request.app))
    return web.json_response(
        {"ok": True, "notice": state.get("last_notice", "")},
        dumps=lambda x: json.dumps(x, ensure_ascii=False),
    )


async def disconnect(request: web.Request) -> web.Response:
    state = _read_state()
    client_login = str(state.get("client_login", "")).strip()
    if not client_login:
        return web.json_response({"ok": False, "error": "Brak aktywnego klienta."}, status=400)

    runtime: dict[str, Any] = request.app["runtime"]
    heartbeat_task: asyncio.Task | None = runtime.get("heartbeat_task")
    if heartbeat_task and not heartbeat_task.done():
        heartbeat_task.cancel()

    try:
        await _operator_post("/api/v1/disconnect", {"client_login": client_login})
    except web.HTTPException:
        pass

    await request.app["tailscale"].disconnect()
    await request.app["ha_relay"].stop()
    state["connected"] = False
    state["tailscale_ip"] = ""
    state["tailscale_node"] = ""
    state["dashboard_url"] = ""
    state["last_error"] = ""
    state["last_notice"] = ""
    _write_state(state)
    return web.json_response({"ok": True}, dumps=lambda x: json.dumps(x, ensure_ascii=False))


async def _heartbeat_loop(app: web.Application) -> None:
    while True:
        try:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            state = _read_state()
            if not state.get("connected"):
                return
            tailscale_info = await app["tailscale"].status()
            state["tailscale_ip"] = tailscale_info.get("tailscale_ip", "")
            state["tailscale_node"] = tailscale_info.get("tailscale_node", "")
            state["connected"] = tailscale_info.get("connected") == "true"
            state["dashboard_url"] = _build_dashboard_url(state.get("tailscale_ip", ""))
            state["last_error"] = ""
            if not state.get("connected"):
                state["last_notice"] = ""
                state["dashboard_url"] = ""
            _write_state(state)
            await _operator_post(
                "/api/v1/heartbeat",
                {
                    "client_login": state.get("client_login", ""),
                    "tailscale_ip": state.get("tailscale_ip", ""),
                    "tailscale_node": state.get("tailscale_node", ""),
                    "dashboard_url": state.get("dashboard_url", ""),
                },
            )
            poll_payload = await _operator_post("/api/v1/poll", {"client_login": state.get("client_login", "")})
            job = poll_payload.get("job") if isinstance(poll_payload, dict) else None
            if isinstance(job, dict) and str(job.get("job_id", "")).strip():
                await _run_operator_job(job)
            state = _read_state()
            if state.get("connected"):
                if state.get("last_error"):
                    state["last_error"] = ""
                _write_state(state)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            state = _read_state()
            if state.get("connected"):
                state["last_error"] = ""
            else:
                state["last_error"] = str(exc).strip() or "Utracono połączenie z operatorem lub Tailscale."
            _write_state(state)


async def on_startup(app: web.Application) -> None:
    _ensure_state_file()
    state = _read_state()
    if TAILSCALE_AUTHKEY and state.get("last_error") == MISSING_TAILSCALE_KEY_ERROR:
        state["last_error"] = ""
        _write_state(state)
        state = _read_state()
    if state.get("connected") and state.get("client_login"):
        try:
            tailscale_info = await app["tailscale"].status()
            state["tailscale_ip"] = tailscale_info.get("tailscale_ip", "")
            state["tailscale_node"] = tailscale_info.get("tailscale_node", "")
            state["connected"] = tailscale_info.get("connected") == "true"
            state["dashboard_url"] = _build_dashboard_url(state.get("tailscale_ip", ""))
            _write_state(state)
        except Exception:
            state["connected"] = False
            state["dashboard_url"] = ""
            _write_state(state)
        if state.get("connected"):
            state["last_error"] = ""
            await app["ha_relay"].start()
            app["tailscale"].reset_serve()
            _write_state(state)
            app["runtime"]["heartbeat_task"] = asyncio.create_task(_heartbeat_loop(app))


async def on_cleanup(app: web.Application) -> None:
    runtime: dict[str, Any] = app["runtime"]
    heartbeat_task: asyncio.Task | None = runtime.get("heartbeat_task")
    if heartbeat_task and not heartbeat_task.done():
        heartbeat_task.cancel()
    state = _read_state()
    client_login = str(state.get("client_login", "")).strip()
    if state.get("connected") and client_login:
        try:
            await _operator_post("/api/v1/disconnect", {"client_login": client_login})
        except web.HTTPException:
            pass
    await app["ha_relay"].stop()
    await app["tailscale"].disconnect()


def create_app() -> web.Application:
    app = web.Application()
    app["tailscale"] = TailscaleAdapter()
    app["ha_relay"] = LocalTcpRelay()
    app["runtime"] = {"heartbeat_task": None}
    app.router.add_get("/", index)
    app.router.add_get("/api/status", status)
    app.router.add_get("/api/capabilities", capabilities)
    app.router.add_post("/api/connect", connect)
    app.router.add_post("/api/disconnect", disconnect)
    app.router.add_static("/static", STATIC_DIR)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    _ensure_state_file()
    web.run_app(create_app(), host="0.0.0.0", port=8099)
