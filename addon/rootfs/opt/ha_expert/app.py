from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
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
DEFAULT_HA_LOG_LINES = 180
SUPERVISOR_URL = os.environ.get("SUPERVISOR_URL", "http://supervisor").rstrip("/")
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "").strip()


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
            self._run(["tailscale", "--socket", TAILSCALE_SOCKET, "logout"], check=False)
        finally:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    self._proc.kill()
            self._proc = None


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


def _read_ha_log_tail(lines: int = DEFAULT_HA_LOG_LINES) -> dict[str, Any]:
    lines = max(20, min(lines, 500))
    try:
        return _read_ha_log_tail_via_supervisor(lines)
    except Exception:
        log_file = _resolve_ha_log_file()
        content = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = content[-lines:]
        return {
            "source": str(log_file),
            "lines": lines,
            "text": "\n".join(selected),
        }


async def _run_operator_job(job: dict[str, Any]) -> None:
    job_id = str(job.get("job_id", "")).strip()
    kind = str(job.get("kind", "")).strip()
    payload = job.get("payload", {}) if isinstance(job.get("payload"), dict) else {}
    if not job_id:
        return

    try:
        if kind == "ha_log_tail":
            result = _read_ha_log_tail(int(payload.get("lines", DEFAULT_HA_LOG_LINES) or DEFAULT_HA_LOG_LINES))
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
    except Exception as exc:
        state["client_login"] = client_login
        state["ha_token"] = ha_token
        state["connected"] = False
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
    }
    try:
        await _operator_post("/api/v1/connect", operator_payload)
    except web.HTTPException as exc:
        state["connected"] = False
        state["tailscale_ip"] = ""
        state["tailscale_node"] = ""
        state["last_error"] = exc.text or "Nie udało się zarejestrować połączenia."
        _write_state(state)
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
    state["connected"] = False
    state["tailscale_ip"] = ""
    state["tailscale_node"] = ""
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
            state["last_error"] = ""
            if not state.get("connected"):
                state["last_notice"] = ""
            _write_state(state)
            await _operator_post(
                "/api/v1/heartbeat",
                {
                    "client_login": state.get("client_login", ""),
                    "tailscale_ip": state.get("tailscale_ip", ""),
                    "tailscale_node": state.get("tailscale_node", ""),
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
            _write_state(state)
        except Exception:
            state["connected"] = False
            _write_state(state)
        if state.get("connected"):
            state["last_error"] = ""
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
    await app["tailscale"].disconnect()


def create_app() -> web.Application:
    app = web.Application()
    app["tailscale"] = TailscaleAdapter()
    app["runtime"] = {"heartbeat_task": None}
    app.router.add_get("/", index)
    app.router.add_get("/api/status", status)
    app.router.add_post("/api/connect", connect)
    app.router.add_post("/api/disconnect", disconnect)
    app.router.add_static("/static", STATIC_DIR)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    _ensure_state_file()
    web.run_app(create_app(), host="0.0.0.0", port=8099)
