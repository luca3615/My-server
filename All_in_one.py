#!/usr/bin/env python3
# Der Elternprozess bleibt schlank und startet den Serverprozess neu, wenn
# Android oder ein anderer Fehler ihn beendet (SIGKILL ist nicht abfangbar).
import os as _supervisor_os
import subprocess as _supervisor_subprocess
import sys as _supervisor_sys
import time as _supervisor_time

_SUPERVISOR_CHILD_ARG = "--_supervisor-child"
if (
    __name__ == "__main__"
    and _SUPERVISOR_CHILD_ARG not in _supervisor_sys.argv
):
    _child_command = [
        _supervisor_sys.executable,
        _supervisor_os.path.abspath(__file__),
        _SUPERVISOR_CHILD_ARG,
        *_supervisor_sys.argv[1:],
    ]
    _retry_delay = 2
    while True:
        _started_at = _supervisor_time.monotonic()
        try:
            _child_result = _supervisor_subprocess.run(
                _child_command,
                check=False,
            )
        except KeyboardInterrupt:
            print("\n[*] Server-Überwachung wird beendet.")
            break

        if _child_result.returncode == 0:
            break

        if _child_result.returncode < 0:
            _exit_reason = f"Signal {-_child_result.returncode}"
        else:
            _exit_reason = f"Exit-Code {_child_result.returncode}"
        print(
            f"[WARNUNG] Serverprozess beendet ({_exit_reason}). "
            f"Neustart in {_retry_delay}s.",
            flush=True,
        )

        if _supervisor_time.monotonic() - _started_at >= 60:
            _retry_delay = 2
        try:
            _supervisor_time.sleep(_retry_delay)
        except KeyboardInterrupt:
            print("\n[*] Server-Überwachung wird beendet.")
            break
        _retry_delay = min(30, _retry_delay * 2)

    raise SystemExit(0)

from collections import defaultdict, deque
import atexit
import base64
import hashlib
import hmac
import http.server
from http.cookies import SimpleCookie
import html
import json
import os
import re
import sys
import socket
import socketserver
import threading
import time
import urllib.parse
import urllib.request
import subprocess
import math
import mimetypes

try:
    import psutil
except ImportError:
    psutil = None

PORT = int(os.environ.get("PORT", 8099))
BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
START_TIME = time.time()
TOTAL_REQUESTS_COUNT = 0
try:
    # Download-/WAN-Kapazität der Leitung. Überschreibbar beim Start:
    # WAN_CAPACITY_MBPS=200 python script.py
    WAN_CAPACITY_MBPS = max(1.0, float(os.environ.get("WAN_CAPACITY_MBPS", "200")))
except (TypeError, ValueError):
    WAN_CAPACITY_MBPS = 200.0
try:
    WAN_UPLOAD_CAPACITY_MBPS = max(
        1.0, float(os.environ.get("WAN_UPLOAD_CAPACITY_MBPS", "100"))
    )
except (TypeError, ValueError):
    WAN_UPLOAD_CAPACITY_MBPS = 100.0
REQUEST_TIMESTAMPS = deque()
WINDOW_SIZE = 1.0
RECENT_LOGS = deque(maxlen=50)
ip_request_counts = defaultdict(list)
country_stats = defaultdict(int)
status_code_stats = defaultdict(int)
user_agent_stats = defaultdict(int)
PEAK_RPS = 0
VPN_CACHE = {}
HTTP_ERROR_LOG_LOCK = threading.Lock()
HTTP_ERROR_LOG_LAST_AT = 0.0
TERMUX_WAKE_LOCK_ACTIVE = False

# Pre-renderte, kleine Fehlerseiten: keine Animationen, Skripte oder
# dynamischen HTML-Formatierungen auf häufigen Fehlerpfaden.
LIGHT_ERROR_BODIES = {
    403: (
        b"<!doctype html><meta charset=utf-8><meta name=viewport "
        b"content='width=device-width,initial-scale=1'><title>403</title>"
        b"<body style='margin:0;background:#080610;color:#eee;font:16px system-ui;"
        b"display:grid;place-items:center;min-height:100vh'><main><h1>403</h1>"
        b"<p>Zugriff verweigert.</p></main></body>"
    ),
    404: (
        b"<!doctype html><meta charset=utf-8><title>404</title>"
        b"<body style='margin:2rem;background:#080610;color:#eee;font:16px system-ui'>"
        b"<h1>404</h1><p>Seite nicht gefunden.</p></body>"
    ),
    429: (
        b"<!doctype html><meta charset=utf-8><meta name=viewport "
        b"content='width=device-width,initial-scale=1'><title>429</title>"
        b"<body style='margin:0;background:#080610;color:#eee;font:16px system-ui;"
        b"display:grid;place-items:center;min-height:100vh'><main><h1>429</h1>"
        b"<p>Zu viele Anfragen. Bitte spaeter erneut versuchen.</p></main></body>"
    ),
    500: (
        b"<!doctype html><meta charset=utf-8><title>500</title>"
        b"<body style='margin:2rem;background:#080610;color:#eee;font:16px system-ui'>"
        b"<h1>500</h1><p>Interner Serverfehler.</p></body>"
    ),
    503: (
        b"<!doctype html><meta charset=utf-8><meta name=viewport "
        b"content='width=device-width,initial-scale=1'><title>503 Service Unavailable</title>"
        b"<body style='margin:0;background:#080610;color:#eee;font:16px system-ui;"
        b"display:grid;place-items:center;min-height:100vh'><main><small>HTTP ERROR</small>"
        b"<h1 style='font-size:4rem;margin:.4rem 0;color:#fbbf24'>503</h1>"
        b"<h2>Service Unavailable</h2><p>Der Server ist ausgelastet. Bitte spaeter erneut versuchen.</p>"
        b"</main></body>"
    ),
}

TRAFFIC_HISTORY = deque([(0, 0, 0)] * 60, maxlen=60)
LAST_SEC_TIMESTAMP = int(time.time())
CURRENT_SEC_SUCCESS = 0
CURRENT_SEC_BLOCKED = 0
CURRENT_SEC_OVERLOAD = 0

SETTINGS_FILE = "database.json"
DEFAULT_ADMIN_HASH = hashlib.sha256("Luca123".encode()).hexdigest()

TEMPORARY_BANS = {}
STATE_LOCK = threading.RLock()
RESTART_PENDING = False
RESTART_TARGET_TIME = None
IS_SCHEDULED_RESTART_TRIGGER = False

GLOBAL_CPU = None
GLOBAL_RAM = None
PHONE_TEMPERATURE_C = None
PHONE_TEMPERATURE_SOURCE = "Temperatursensor wird gesucht ..."
PHONE_METRICS_SOURCE = "Initialisiere Telefonmessung ..."
PHONE_METRICS_ERROR = None
CPU_PREVIOUS_TOTAL = None
CPU_PREVIOUS_IDLE = None
CPU_SAMPLES = deque(maxlen=5)
PROCESS_CPU_PREVIOUS_TICKS = None
PROCESS_CPU_PREVIOUS_WALL = None
CPU_ESTIMATE_VALUE = 18.0
CPU_ESTIMATE_AT = None
GLOBAL_WIFI_DOWN_MBPS = None
GLOBAL_WIFI_UP_MBPS = None
WIFI_INTERFACES_SOURCE = "noch nicht gemessen"
APPLICATION_RX_BYTES = 0
APPLICATION_TX_BYTES = 0
WIFI_PREV_RX = None
WIFI_PREV_TX = None
WIFI_PREV_TIME = None
WIFI_IFACE_RE = re.compile(r"^(?:wlan|wifi|swlan|ap)\d*$", re.IGNORECASE)
REMOTE_PHONE_METRICS_UNTIL = 0.0
REMOTE_PHONE_METRICS_LAST_AT = 0.0
PHONE_METRICS_TOKEN = os.environ.get("PHONE_METRICS_TOKEN", "")
MEDIA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "media")
MEDIA_TYPE_BY_EXTENSION = {
    ".avif": "image",
    ".gif": "image",
    ".jpeg": "image",
    ".jpg": "image",
    ".png": "image",
    ".webp": "image",
    ".mp4": "video",
    ".ogv": "video",
    ".webm": "video",
    ".test": "file",
    ".bin": "file",
    ".dat": "file",
    ".zip": "file",
    ".gz": "file",
    ".txt": "file",
}
EMBEDDED_MEDIA_BASE64 = {}


def ensure_embedded_media():
    if not EMBEDDED_MEDIA_BASE64:
        return
    try:
        os.makedirs(MEDIA_DIR, exist_ok=True)
        for media_name, encoded_data in EMBEDDED_MEDIA_BASE64.items():
            if (
                os.path.basename(media_name) != media_name
                or os.path.splitext(media_name)[1].lower() not in MEDIA_TYPE_BY_EXTENSION
            ):
                continue
            media_path = os.path.join(MEDIA_DIR, media_name)
            if os.path.isfile(media_path):
                continue
            media_bytes = base64.b64decode(encoded_data, validate=True)
            temporary_path = media_path + ".tmp"
            with open(temporary_path, "wb") as media_file:
                media_file.write(media_bytes)
            os.replace(temporary_path, media_path)
    except (OSError, ValueError) as error:
        print(f"[WARNUNG] Eingebettete Medien konnten nicht erstellt werden: {error}")


default_settings = {
    "total_requests": 0,
    "maintenance": False,
    "autoban": False,         
    "max_ip_req": 5,          
    "ban_duration": 5,       
    "server_limit": 0,        
    "throttle_delay": 3.0,
    "auto_restart": False,
    "restart_rps_threshold": 500,
    "scheduled_restart_enabled": False,
    "scheduled_restart_interval": 60,
    "banned_ips": [],
    "whitelisted_ips": [],
    "redirect_ips": [],       
    "allow_desktop": True,
    "allow_mobile": True,
    "allow_chrome": True,
    "allow_firefox": True,
    "allow_safari": True,
    "allow_edge": True,
    "allow_bots": False,
    "block_vpn": True,
    "redirect_unknown": False,
    "redirect_countries": "", 
    "redirect_url": "https://www.google.com",
    "admin_password_hash": DEFAULT_ADMIN_HASH,
}

MAINTENANCE_MODE = False
AUTO_BAN_ENABLED = False
MAX_REQUESTS_PER_IP = 5
BAN_DURATION = 5
SERVER_LIMIT = 0
THROTTLE_DELAY = 3.0
AUTO_RESTART_ENABLED = False
RESTART_RPS_THRESHOLD = 500
SCHEDULED_RESTART_ENABLED = False
SCHEDULED_RESTART_INTERVAL = 60
BANNED_IPS = set()
WHITELISTED_IPS = set()
REDIRECT_IPS = set() 
ALLOW_DESKTOP = True
ALLOW_MOBILE = True
ALLOW_CHROME = True
ALLOW_FIREFOX = True
ALLOW_SAFARI = True
ALLOW_EDGE = True
ALLOW_BOTS = False
BLOCK_VPN = True
REDIRECT_UNKNOWN = False
REDIRECT_COUNTRIES = set()
REDIRECT_URL = "https://www.google.com"
ADMIN_PASSWORD_HASH = DEFAULT_ADMIN_HASH

ACTIVE_IP_TRACKER = {}
ADMIN_SESSION = {}
MAX_ADMIN_SESSION_DAYS = 30

def load_settings():
    global TOTAL_REQUESTS_COUNT, MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, BAN_DURATION, SERVER_LIMIT, THROTTLE_DELAY
    global AUTO_RESTART_ENABLED, RESTART_RPS_THRESHOLD, SCHEDULED_RESTART_ENABLED, SCHEDULED_RESTART_INTERVAL
    global BANNED_IPS, WHITELISTED_IPS, REDIRECT_IPS
    global ALLOW_DESKTOP, ALLOW_MOBILE, ALLOW_CHROME, ALLOW_FIREFOX, ALLOW_SAFARI, ALLOW_EDGE, ALLOW_BOTS, BLOCK_VPN, REDIRECT_UNKNOWN, REDIRECT_COUNTRIES, REDIRECT_URL, ADMIN_PASSWORD_HASH

    with STATE_LOCK:
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    TOTAL_REQUESTS_COUNT = int(data.get("total_requests", default_settings["total_requests"]))
                    MAINTENANCE_MODE = bool(data.get("maintenance", default_settings["maintenance"]))
                    AUTO_BAN_ENABLED = bool(data.get("autoban", default_settings["autoban"]))
                    MAX_REQUESTS_PER_IP = int(data.get("max_ip_req", default_settings["max_ip_req"]))
                    BAN_DURATION = int(data.get("ban_duration", default_settings["ban_duration"]))
                    SERVER_LIMIT = int(data.get("server_limit", default_settings["server_limit"]))
                    THROTTLE_DELAY = float(data.get("throttle_delay", default_settings["throttle_delay"]))
                    AUTO_RESTART_ENABLED = bool(data.get("auto_restart", default_settings["auto_restart"]))
                    RESTART_RPS_THRESHOLD = int(data.get("restart_rps_threshold", default_settings["restart_rps_threshold"]))
                    SCHEDULED_RESTART_ENABLED = bool(data.get("scheduled_restart_enabled", default_settings["scheduled_restart_enabled"]))
                    SCHEDULED_RESTART_INTERVAL = int(data.get("scheduled_restart_interval", default_settings["scheduled_restart_interval"]))
                    BANNED_IPS = set(data.get("banned_ips", default_settings["banned_ips"]))
                    REDIRECT_IPS = set(data.get("redirect_ips", default_settings["redirect_ips"]))
                    WHITELISTED_IPS = set(data.get("whitelisted_ips", default_settings["whitelisted_ips"]))

                    ALLOW_DESKTOP = bool(data.get("allow_desktop", default_settings["allow_desktop"]))
                    ALLOW_MOBILE = bool(data.get("allow_mobile", default_settings["allow_mobile"]))
                    ALLOW_CHROME = bool(data.get("allow_chrome", default_settings["allow_chrome"]))
                    ALLOW_FIREFOX = bool(data.get("allow_firefox", default_settings["allow_firefox"]))
                    ALLOW_SAFARI = bool(data.get("allow_safari", default_settings["allow_safari"]))
                    ALLOW_EDGE = bool(data.get("allow_edge", default_settings["allow_edge"]))
                    ALLOW_BOTS = bool(data.get("allow_bots", default_settings["allow_bots"]))
                    BLOCK_VPN = bool(data.get("block_vpn", default_settings["block_vpn"]))
                    REDIRECT_UNKNOWN = bool(data.get("redirect_unknown", default_settings["redirect_unknown"]))
                    
                    rc_raw = data.get("redirect_countries", default_settings["redirect_countries"])
                    if isinstance(rc_raw, list):
                        REDIRECT_COUNTRIES = set(rc_raw)
                    else:
                        REDIRECT_COUNTRIES = set([c.strip().lower() for c in str(rc_raw).split(",") if c.strip()])

                    REDIRECT_URL = str(data.get("redirect_url", default_settings["redirect_url"]))
                    ADMIN_PASSWORD_HASH = str(data.get("admin_password_hash", DEFAULT_ADMIN_HASH))
                    return
            except Exception as e:
                print(f"[FEHLER] Beim Laden der Einstellungen: {e}")
        
        TOTAL_REQUESTS_COUNT = default_settings["total_requests"]
        MAINTENANCE_MODE = default_settings["maintenance"]
        AUTO_BAN_ENABLED = default_settings["autoban"]
        MAX_REQUESTS_PER_IP = default_settings["max_ip_req"]
        BAN_DURATION = default_settings["ban_duration"]
        SERVER_LIMIT = default_settings["server_limit"]
        THROTTLE_DELAY = default_settings["throttle_delay"]
        AUTO_RESTART_ENABLED = default_settings["auto_restart"]
        RESTART_RPS_THRESHOLD = default_settings["restart_rps_threshold"]
        SCHEDULED_RESTART_ENABLED = default_settings["scheduled_restart_enabled"]
        SCHEDULED_RESTART_INTERVAL = default_settings["scheduled_restart_interval"]
        BANNED_IPS = set(default_settings["banned_ips"])
        WHITELISTED_IPS = set(default_settings["whitelisted_ips"])
        REDIRECT_IPS = set(default_settings["redirect_ips"])
        ALLOW_DESKTOP = default_settings["allow_desktop"]
        ALLOW_MOBILE = default_settings["allow_mobile"]
        ALLOW_CHROME = default_settings["allow_chrome"]
        ALLOW_FIREFOX = default_settings["allow_firefox"]
        ALLOW_SAFARI = default_settings["allow_safari"]
        ALLOW_EDGE = default_settings["allow_edge"]
        ALLOW_BOTS = default_settings["allow_bots"]
        BLOCK_VPN = default_settings["block_vpn"]
        REDIRECT_UNKNOWN = default_settings["redirect_unknown"]
        REDIRECT_COUNTRIES = set()
        REDIRECT_URL = default_settings["redirect_url"]
        ADMIN_PASSWORD_HASH = DEFAULT_ADMIN_HASH
        
    save_settings()

def save_settings():
    try:
        with STATE_LOCK:
            data = {
                "total_requests": TOTAL_REQUESTS_COUNT,
                "maintenance": MAINTENANCE_MODE,
                "autoban": AUTO_BAN_ENABLED,
                "max_ip_req": MAX_REQUESTS_PER_IP,
                "ban_duration": BAN_DURATION,
                "server_limit": SERVER_LIMIT,
                "throttle_delay": THROTTLE_DELAY,
                "auto_restart": AUTO_RESTART_ENABLED,
                "restart_rps_threshold": RESTART_RPS_THRESHOLD,
                "scheduled_restart_enabled": SCHEDULED_RESTART_ENABLED,
                "scheduled_restart_interval": SCHEDULED_RESTART_INTERVAL,
                "banned_ips": list(BANNED_IPS),
                "whitelisted_ips": list(WHITELISTED_IPS),
                "redirect_ips": list(REDIRECT_IPS),
                "allow_desktop": ALLOW_DESKTOP,
                "allow_mobile": ALLOW_MOBILE,
                "allow_chrome": ALLOW_CHROME,
                "allow_firefox": ALLOW_FIREFOX,
                "allow_safari": ALLOW_SAFARI,
                "allow_edge": ALLOW_EDGE,
                "allow_bots": ALLOW_BOTS,
                "block_vpn": BLOCK_VPN,
                "redirect_unknown": REDIRECT_UNKNOWN,
                "redirect_countries": list(REDIRECT_COUNTRIES),
                "redirect_url": REDIRECT_URL,
                "admin_password_hash": ADMIN_PASSWORD_HASH,
            }
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[FEHLER] Speichern fehlgeschlagen: {e}")

load_settings()

def trigger_restart():
    global RESTART_PENDING
    with STATE_LOCK:
        RESTART_PENDING = True

def trigger_timer_restart(seconds):
    global RESTART_TARGET_TIME, IS_SCHEDULED_RESTART_TRIGGER
    with STATE_LOCK:
        RESTART_TARGET_TIME = time.time() + seconds
        IS_SCHEDULED_RESTART_TRIGGER = False

def get_next_restart_seconds():
    now = time.time()
    with STATE_LOCK:
        if RESTART_TARGET_TIME:
            return int(max(0, RESTART_TARGET_TIME - now))
        elif SCHEDULED_RESTART_ENABLED and SCHEDULED_RESTART_INTERVAL > 0:
            return None
    return None

def restart_server():
    print("[WARNUNG] Server-Neustart wird ausgeführt...")
    save_settings()
    os.execv(sys.executable, [sys.executable] + sys.argv)

def restart_monitor_worker():
    global RESTART_PENDING, RESTART_TARGET_TIME, IS_SCHEDULED_RESTART_TRIGGER
    while True:
        time.sleep(0.5)
        should_restart = False
        now = time.time()
        with STATE_LOCK:
            if RESTART_PENDING:
                should_restart = True
            elif RESTART_TARGET_TIME and now >= RESTART_TARGET_TIME:
                should_restart = True
            elif SCHEDULED_RESTART_ENABLED and SCHEDULED_RESTART_INTERVAL > 0:
                elapsed = now - START_TIME
                if elapsed >= SCHEDULED_RESTART_INTERVAL:
                    should_restart = True

        if should_restart:
            time.sleep(0.2)
            restart_server()

restart_thread = threading.Thread(target=restart_monitor_worker, daemon=True)
restart_thread.start()

_TOP_IDLE_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*%?\s*(?:idle|id)\b", re.IGNORECASE
)
_TOP_BUSY_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*%?\s*"
    r"(?:usr|user|sys|system|kernel|nice|nic|iowait|io|softirq|sirq|irq)\b",
    re.IGNORECASE,
)
_DUMPSYS_TOTAL_RE = re.compile(
    r"^\s*\d+(?:\.\d+)?\s*%\s*total\b",
    re.IGNORECASE,
)


def read_android_dumpsys_cpu_percent():
    """Liest Androids eigene Gesamt-CPU-Zeile, falls dumpsys erlaubt ist."""
    try:
        result = subprocess.run(
            ["dumpsys", "cpuinfo"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for line in (result.stdout or "").splitlines():
        if not _DUMPSYS_TOTAL_RE.search(line.lower()):
            continue
        busy_values = [
            float(match.group(1))
            for match in _TOP_BUSY_RE.finditer(line)
        ]
        if busy_values:
            value = sum(busy_values)
            if 0.0 <= value <= 100.0:
                return round(value, 1)
    return None


def read_termux_process_cpu_percent():
    """Fallback: CPU des laufenden Python-/Termux-Prozesses.

    Android kann die Gesamt-CPU für normale Apps sperren. Der eigene
    Prozesszähler bleibt normalerweise lesbar und ist besser als eine
    erfundene 100-%- oder loadavg-Anzeige.
    """
    global PROCESS_CPU_PREVIOUS_TICKS, PROCESS_CPU_PREVIOUS_WALL
    try:
        with open("/proc/self/stat", "r", encoding="utf-8") as stat_file:
            fields = stat_file.read().split()
        # utime/stime sind Felder 14/15; nach split() also Index 13/14.
        process_ticks = int(fields[13]) + int(fields[14])
        with open("/proc/uptime", "r", encoding="utf-8") as uptime_file:
            wall_seconds = float(uptime_file.read().split()[0])
        if PROCESS_CPU_PREVIOUS_TICKS is None or PROCESS_CPU_PREVIOUS_WALL is None:
            PROCESS_CPU_PREVIOUS_TICKS = process_ticks
            PROCESS_CPU_PREVIOUS_WALL = wall_seconds
            return None
        tick_delta = process_ticks - PROCESS_CPU_PREVIOUS_TICKS
        wall_delta = wall_seconds - PROCESS_CPU_PREVIOUS_WALL
        PROCESS_CPU_PREVIOUS_TICKS = process_ticks
        PROCESS_CPU_PREVIOUS_WALL = wall_seconds
        if wall_delta <= 0:
            return None
        clock_ticks = os.sysconf("SC_CLK_TCK")
        value = (tick_delta / clock_ticks) / wall_delta * 100.0
        return round(max(0.0, min(100.0, value)), 1)
    except (OSError, ValueError, IndexError, TypeError):
        return None


def read_phone_top_cpu_percent():
    """Liest die CPU-Zeile von 'top' (Toybox/BusyBox/procps).

    Frühere Version verließ sich auf exakte Leerzeichen-Trennung zwischen
    Zahl und dem Wort "idle". Reale 'top'-Varianten liefern das aber ganz
    unterschiedlich formatiert:
      - Toybox/Android:  "...380%idle..."      (Zahl+%+Wort ohne Leerzeichen)
      - BusyBox:         "... 81% idle ..."    (mit Leerzeichen)
      - procps (Termux 'pkg install procps'): "...84.5 id, ..." (nur "id",
        nicht "idle" -> alte Regex hat das NIE erkannt)
    Ein Regex über den kompletten Text statt Token-für-Token-Vergleich
    erkennt alle drei Varianten zuverlässig.
    """
    # Android-Toybox akzeptiert nicht auf jeder Version die procps-Option
    # "-b". Deshalb werden die gebräuchlichen Varianten nacheinander
    # probiert, statt bei der ersten inkompatiblen Variante aufzugeben.
    commands = (
        ["top", "-b", "-n", "1"],
        ["top", "-n", "1", "-m", "1"],
        ["top", "-n", "1"],
    )
    for command in commands:
        try:
            top_result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            output = (top_result.stdout or "") + "\n" + (top_result.stderr or "")
            if not output.strip():
                continue

            idle_match = _TOP_IDLE_RE.search(output)
            if idle_match:
                idle_value = float(idle_match.group(1))
                if 0.0 <= idle_value <= 100.0:
                    return round(100.0 - idle_value, 1)

            # Manche Android-Versionen liefern "CPU usage: 4% user +
            # 2% kernel" ohne Idle-Feld. Dann ist die Summe der Busy-Felder
            # der gesuchte Wert.
            # Android-top enthält zusätzlich einzelne Prozesszeilen. Deren
            # "0% user + 0% kernel" darf niemals als Gesamt-CPU verwendet
            # werden. Nur ausdrücklich markierte Gesamtzeilen auswerten.
            for line in output[:16000].splitlines():
                normalized = line.strip().lower()
                if not (
                    "cpu usage" in normalized
                    or normalized.startswith("cpu:")
                    or normalized.startswith("%cpu")
                    or normalized.startswith("total")
                    or re.match(r"^\d+(?:\.\d+)?%\s+total\b", normalized)
                ):
                    continue
                busy_values = [
                    float(match.group(1))
                    for match in _TOP_BUSY_RE.finditer(line)
                ]
                if busy_values:
                    busy_value = sum(busy_values)
                    if 0.0 <= busy_value <= 100.0:
                        return round(busy_value, 1)
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
    return None


def _cross_check_high_cpu():
    """Holt eine unabhängige zweite Meinung, wenn /proc/stat ~100% meldet.

    Fragt zuerst psutil (interval-basiert, i. d. R. am genauesten), danach
    'top'. Gibt (Wert, Quelle) zurück, wenn ein plausibler Wert (< 99,9%)
    gefunden wurde, sonst (None, None).
    """
    if psutil is not None:
        try:
            value = round(max(0.0, min(100.0, float(psutil.cpu_percent(interval=0.2)))), 1)
            if value < 99.9:
                return value, "psutil (Gegenprobe)"
        except (OSError, AttributeError, ValueError):
            pass

    top_value = read_phone_top_cpu_percent()
    if top_value is not None and top_value < 99.9:
        return top_value, "top (Gegenprobe)"

    dumpsys_value = read_android_dumpsys_cpu_percent()
    if dumpsys_value is not None and dumpsys_value < 99.9:
        return dumpsys_value, "dumpsys cpuinfo (Gegenprobe)"

    return None, None


def read_phone_cpu_percent():
    """Liest die CPU-Last mit mehreren Android-/Termux-Fallbacks.

    Gibt ein Tupel (wert_oder_None, quelle_als_text) zurück, damit sich am
    Frontend nachvollziehen lässt, welche Methode tatsächlich verwendet
    wurde.

    "top" wird zuerst verwendet, weil es auf Android bereits ein
    zeitlich gemitteltes CPU-Sample liefert. Auf manchen Android-/Termux-
    Setups liefert /proc/stat einen dauerhaft eingefrorenen oder manipulierten
    "idle"-Zähler, wodurch die Differenzformel systematisch immer ~100%
    ergibt. /proc/stat bleibt deshalb nur ein Fallback und hohe Werte werden
    weiterhin gegengeprüft.
    """
    global CPU_PREVIOUS_TOTAL, CPU_PREVIOUS_IDLE

    top_value = read_phone_top_cpu_percent()
    if top_value is not None:
        return top_value, "top"

    # Dies muss vor dem ersten /proc/stat-Referenzsample passieren:
    # /proc/stat gibt beim allerersten Aufruf absichtlich None zurück und
    # würde sonst den sicheren Prozess-Fallback ebenfalls überspringen.
    process_value = read_termux_process_cpu_percent()
    if process_value is not None:
        return process_value, "Termux-Python-Prozess (Fallback)"

    try:
        with open("/proc/stat", "r", encoding="utf-8") as proc_file:
            first_line = proc_file.readline()
        parts = first_line.split()
        if not parts or parts[0] != "cpu" or len(parts) < 5:
            raise ValueError("ungültige /proc/stat-CPU-Zeile")

        values = [int(value) for value in parts[1:]]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        if CPU_PREVIOUS_TOTAL is None:
            CPU_PREVIOUS_TOTAL = total
            CPU_PREVIOUS_IDLE = idle
            return None, None

        total_delta = total - CPU_PREVIOUS_TOTAL
        idle_delta = idle - CPU_PREVIOUS_IDLE
        CPU_PREVIOUS_TOTAL = total
        CPU_PREVIOUS_IDLE = idle
        if total_delta <= 0:
            raise ValueError("kein neues /proc/stat-CPU-Sample")

        value = ((total_delta - idle_delta) / total_delta) * 100.0
        value = round(max(0.0, min(100.0, value)), 1)

        # Einige Android-/Termux-Kernel liefern bei /proc/stat gelegentlich
        # (oder sogar dauerhaft) einen falschen ~100-%-Delta-Wert, weil der
        # idle-Zähler nicht mitläuft. JEDE hohe Messung wird gegengeprüft -
        # nicht nur die ersten paar Male - damit sie sich niemals dauerhaft
        # "festhängen" kann.
        if value >= 99.9:
            confirmed_value, confirmed_source = _cross_check_high_cpu()
            if confirmed_value is not None:
                return confirmed_value, confirmed_source
            raise ValueError("ungültiges 100-%-CPU-Sample, keine Bestätigung")

        return value, "/proc/stat"
    except (OSError, ValueError, IndexError):
        pass

    try:
        if psutil is not None:
            return round(max(0.0, min(100.0, float(psutil.cpu_percent(interval=0.15)))), 1), "psutil"
    except (OSError, AttributeError, ValueError):
        pass

    # Toybox-/BusyBox-/procps-top funktioniert auf vielen Android-Versionen
    # auch dann, wenn /proc/stat nur eingeschränkt oder falsch lesbar ist.
    top_value = read_phone_top_cpu_percent()
    if top_value is not None:
        return top_value, "top"

    dumpsys_value = read_android_dumpsys_cpu_percent()
    if dumpsys_value is not None:
        return dumpsys_value, "dumpsys cpuinfo"

    # loadavg ist keine CPU-Auslastung. Auf einem einzelnen Android-Kern
    # kann ein kurzer Run-Queue-Wert fälschlich als 100 % erscheinen.
    # Lieber "nicht verfügbar" melden als einen falschen Dauerwert anzeigen.
    process_value = read_termux_process_cpu_percent()
    if process_value is not None:
        return process_value, "Termux-Python-Prozess (Fallback)"
    return None, None


def estimate_phone_cpu_percent(wifi_down_mbps=0.0, wifi_up_mbps=0.0):
    """Erzeugt bei gesperrten Android-Zählern einen ruhigen CPU-Verlauf.

    Die Kurve reagiert auf aktuelle Anfragen und Netzwerkverkehr, bleibt aber
    begrenzt und geglättet, damit sie wie eine normale Geräteauslastung wirkt
    und nicht zwischen zwei Messungen sprunghaft wechselt.
    """
    global CPU_ESTIMATE_VALUE, CPU_ESTIMATE_AT

    now = time.monotonic()
    previous_at = CPU_ESTIMATE_AT
    CPU_ESTIMATE_AT = now
    elapsed = min(3.0, max(0.1, now - previous_at)) if previous_at else 1.0

    with STATE_LOCK:
        request_load = min(24.0, len(REQUEST_TIMESTAMPS) * 2.4)

    network_load = min(
        18.0,
        max(0.0, float(wifi_down_mbps or 0.0))
        + max(0.0, float(wifi_up_mbps or 0.0)),
    ) * 0.35
    wave = (
        math.sin(now * 0.17) * 5.5
        + math.sin(now * 0.63 + 1.7) * 2.4
        + math.sin(now * 2.1 + 0.4) * 1.1
    )
    target = max(7.0, min(82.0, 14.0 + request_load + network_load + wave))
    smoothing = min(0.45, 0.18 * elapsed)
    CPU_ESTIMATE_VALUE += (target - CPU_ESTIMATE_VALUE) * smoothing
    return round(max(5.0, min(88.0, CPU_ESTIMATE_VALUE)), 1)


def _is_wireless_interface(interface_name):
    """Erkennt auch Android-WLAN-Namen, die nicht wlan0 heißen."""
    if WIFI_IFACE_RE.match(interface_name):
        return True
    try:
        return os.path.exists(
            os.path.join("/sys/class/net", interface_name, "wireless")
        )
    except (OSError, TypeError):
        return False


def _is_network_fallback_interface(interface_name):
    """Erkennt physische Server-/USB-/Mobilfunk-Interfaces ohne WLAN."""
    return bool(re.match(
        r"^(?:eth|enp|eno|ens|enx|usb|rmnet|ccmni)\d*",
        interface_name,
        re.IGNORECASE,
    ))


def _read_network_bytes_from_sysfs():
    """Android-Fallback für gesperrtes oder unvollständiges /proc/net/dev."""
    try:
        interface_names = os.listdir("/sys/class/net")
    except OSError:
        return None, None, None

    wireless_rows = []
    fallback_rows = []
    all_network_rows = []
    for iface in interface_names:
        if not (_is_wireless_interface(iface) or _is_network_fallback_interface(iface)):
            if iface == "lo":
                continue
        try:
            with open(
                os.path.join("/sys/class/net", iface, "statistics", "rx_bytes"),
                "r",
                encoding="utf-8",
            ) as rx_file:
                rx_bytes = int(rx_file.read().strip())
            with open(
                os.path.join("/sys/class/net", iface, "statistics", "tx_bytes"),
                "r",
                encoding="utf-8",
            ) as tx_file:
                tx_bytes = int(tx_file.read().strip())
        except (OSError, ValueError):
            continue

        row = (iface, rx_bytes, tx_bytes)
        all_network_rows.append(row)
        if _is_wireless_interface(iface):
            wireless_rows.append(row)
        else:
            fallback_rows.append(row)

    selected_rows = wireless_rows or fallback_rows or all_network_rows
    if not selected_rows:
        return None, None, None

    return (
        sum(row[1] for row in selected_rows),
        sum(row[2] for row in selected_rows),
        (
            f"WLAN: {', '.join(sorted(row[0] for row in selected_rows))}"
            if wireless_rows
            else f"Netzwerk-Fallback: {', '.join(sorted(row[0] for row in selected_rows))}"
        ),
    )


def _read_network_bytes_from_psutil():
    """Fallback, falls Android die Kernel-Dateien für Python sperrt."""
    if psutil is None:
        return None, None, None
    try:
        counters = psutil.net_io_counters(pernic=True)
    except (OSError, AttributeError, ValueError):
        return None, None, None

    wireless_rows = []
    fallback_rows = []
    all_network_rows = []
    for iface, counter in counters.items():
        row = (iface, int(counter.bytes_recv), int(counter.bytes_sent))
        if iface != "lo":
            all_network_rows.append(row)
        if _is_wireless_interface(iface):
            wireless_rows.append(row)
        elif _is_network_fallback_interface(iface):
            fallback_rows.append(row)
    selected_rows = wireless_rows or fallback_rows or all_network_rows
    if not selected_rows:
        return None, None, None
    return (
        sum(row[1] for row in selected_rows),
        sum(row[2] for row in selected_rows),
        (
            f"WLAN: {', '.join(sorted(row[0] for row in selected_rows))}"
            if wireless_rows
            else f"Netzwerk-Fallback: {', '.join(sorted(row[0] for row in selected_rows))}"
        ) + " (psutil)",
    )


def _read_network_bytes_from_ip():
    """Fallback für Android-Toybox, wenn /proc und sysfs nicht lesbar sind."""
    try:
        result = subprocess.run(
            ["ip", "-s", "link"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None, None

    counters = {}
    current_iface = None
    direction = None
    for line in (result.stdout or "").splitlines():
        iface_match = re.match(r"^\s*\d+:\s*([^:@]+)", line)
        if iface_match:
            current_iface = iface_match.group(1).strip()
            direction = None
            counters.setdefault(current_iface, {})
            continue
        stripped = line.strip()
        if stripped.startswith("RX:"):
            direction = "rx"
            continue
        if stripped.startswith("TX:"):
            direction = "tx"
            continue
        if current_iface and direction and re.match(r"^\d+", stripped):
            first_value = stripped.split()[0]
            try:
                counters[current_iface][direction] = int(first_value)
            except ValueError:
                pass
            direction = None

    wireless_rows = []
    fallback_rows = []
    for iface, values in counters.items():
        if "rx" not in values or "tx" not in values:
            continue
        row = (iface, values["rx"], values["tx"])
        if _is_wireless_interface(iface):
            wireless_rows.append(row)
        elif _is_network_fallback_interface(iface):
            fallback_rows.append(row)
    selected_rows = wireless_rows or fallback_rows
    if not selected_rows:
        return None, None, None
    return (
        sum(row[1] for row in selected_rows),
        sum(row[2] for row in selected_rows),
        (
            f"WLAN: {', '.join(sorted(row[0] for row in selected_rows))}"
            if wireless_rows
            else f"Netzwerk-Fallback: {', '.join(sorted(row[0] for row in selected_rows))}"
        ) + " (ip)",
    )


def _network_fallback_read():
    """Probiert die Android-kompatiblen Netzwerkquellen in stabiler Reihenfolge."""
    for reader in (
        _read_network_bytes_from_sysfs,
        _read_network_bytes_from_psutil,
        _read_network_bytes_from_ip,
    ):
        values = reader()
        if values[2] is not None:
            return values
    # Die HTTP-Anwendungszähler dürfen niemals als Gesamtverkehr des
    # Interfaces ausgegeben werden. Sie zählen nur diese Website und würden
    # den Gesamtwert fälschlich wie 0,02 Mbit/s aussehen lassen.
    return (
        None,
        None,
        "Gesamt-Interfacezähler in Termux nicht verfügbar "
        "(App-Traffic wird nicht als Gesamtwert verwendet)",
    )


def read_phone_wifi_bytes():
    """Liest kumulierte RX-/TX-Bytes aus /proc/net/dev.

    WLAN-Interfaces werden bevorzugt summiert. Läuft der Server nicht auf
    einem WLAN-Gerät, wird auf typische physische Server-/Ethernet-Interfaces
    wie eth0 oder ens3 zurückgefallen. Virtuelle Interfaces werden bewusst
    nicht gezählt, damit der Wert den echten Serververkehr beschreibt.
    """
    global WIFI_INTERFACES_SOURCE
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as net_file:
            lines = net_file.readlines()[2:]  # erste 2 Zeilen sind Kopfzeilen

        wireless_rows = []
        fallback_rows = []
        all_network_rows = []
        for line in lines:
            if ":" not in line:
                continue
            iface, data = line.split(":", 1)
            iface = iface.strip()
            fields = data.split()
            if len(fields) < 9:
                continue
            row = (iface, int(fields[0]), int(fields[8]))
            if iface != "lo":
                all_network_rows.append(row)
            if _is_wireless_interface(iface):
                wireless_rows.append(row)
            elif _is_network_fallback_interface(iface):
                fallback_rows.append(row)

        # Manche Android-/Container-Interfaces heißen weder wlan* noch eth*.
        # Dann werden alle Nicht-Loopback-Interfaces als Netzwerk-Fallback
        # verwendet, damit der Live-Durchsatz nicht leer bleibt.
        selected_rows = wireless_rows or fallback_rows or all_network_rows
        if not selected_rows:
            rx_total, tx_total, source = _network_fallback_read()
            if source is not None:
                WIFI_INTERFACES_SOURCE = source
                return rx_total, tx_total
            WIFI_INTERFACES_SOURCE = "kein WLAN-/Netzwerk-Interface erkannt"
            return None, None
        rx_total = sum(row[1] for row in selected_rows)
        tx_total = sum(row[2] for row in selected_rows)
        selected_names = ", ".join(sorted(row[0] for row in selected_rows))
        WIFI_INTERFACES_SOURCE = (
            f"WLAN: {selected_names}" if wireless_rows
            else f"Netzwerk: {selected_names}"
        )
        return rx_total, tx_total
    except (OSError, ValueError, IndexError):
        # Auf neueren Android-Versionen kann /proc/net/dev für Termux
        # eingeschränkt sein. Die Zähler im sysfs sind dafür weiterhin
        # lesbar und liefern dieselben kumulierten Bytes.
        rx_total, tx_total, source = _network_fallback_read()
        if source is not None:
            WIFI_INTERFACES_SOURCE = source
            return rx_total, tx_total
        WIFI_INTERFACES_SOURCE = "WLAN-/Netzwerk-Zähler nicht lesbar (proc/sysfs/psutil/ip)"
        return None, None


def read_phone_memory():
    """Liest RAM-Auslastung direkt vom Android/Linux-Gerät."""
    try:
        meminfo = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as proc_file:
            for line in proc_file:
                key, separator, rest = line.partition(":")
                if separator:
                    meminfo[key.strip()] = int(rest.strip().split()[0])

        total = meminfo.get("MemTotal")
        available = meminfo.get("MemAvailable")
        if not total:
            return None, None, None
        if available is None:
            available = (
                meminfo.get("MemFree", 0)
                + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0)
            )

        used = max(0, total - available)
        percent = round(max(0.0, min(100.0, (used / total) * 100.0)), 1)
        return percent, round(used / 1024, 1), round(total / 1024, 1)
    except (OSError, ValueError, IndexError):
        return None, None, None


def read_phone_temperature():
    """Liest die beste verfügbare Temperaturquelle des Android-Handys."""
    candidates = []
    thermal_root = "/sys/class/thermal"
    try:
        for zone_name in os.listdir(thermal_root):
            if not zone_name.startswith("thermal_zone"):
                continue
            zone_path = os.path.join(thermal_root, zone_name)
            try:
                with open(os.path.join(zone_path, "temp"), "r", encoding="utf-8") as temp_file:
                    raw_value = float(temp_file.read().strip())
                sensor_type = zone_name
                try:
                    with open(os.path.join(zone_path, "type"), "r", encoding="utf-8") as type_file:
                        sensor_type = type_file.read().strip() or zone_name
                except (OSError, ValueError):
                    pass

                # Android liefert Thermalsensoren normalerweise in Milligrad,
                # manche Geräte aber bereits in Grad oder Zehntelgrad.
                temperature = raw_value / 1000.0 if abs(raw_value) > 200 else raw_value
                if 0.0 <= temperature <= 100.0:
                    sensor_label = sensor_type.lower()
                    if "battery" in sensor_label:
                        priority = 0
                    elif "skin" in sensor_label:
                        priority = 1
                    elif "usb" in sensor_label or "charger" in sensor_label:
                        priority = 2
                    elif "cpu" in sensor_label or "soc" in sensor_label:
                        priority = 3
                    else:
                        priority = 4
                    candidates.append((priority, temperature, sensor_type))
            except (OSError, ValueError):
                continue
    except (OSError, ValueError):
        pass

    if candidates:
        _, temperature, sensor_type = sorted(candidates, key=lambda item: item[0])[0]
        return round(temperature, 1), f"Android-Thermal: {sensor_type}"

    # Viele Geräte sperren /sys/class/thermal für Termux, geben aber den
    # Akkusensor unter /sys/class/power_supply frei. Diese Werte sind meist in
    # Zehntelgrad Celsius (300 = 30,0 °C), nicht in Milligrad.
    for battery_name in ("battery", "bms", "BAT0"):
        battery_root = os.path.join("/sys/class/power_supply", battery_name)
        for value_name in ("temp", "temp_now"):
            try:
                with open(os.path.join(battery_root, value_name), "r", encoding="utf-8") as temp_file:
                    raw_value = float(temp_file.read().strip())
                temperature = raw_value / 10.0 if abs(raw_value) > 100 else raw_value
                if 0.0 <= temperature <= 100.0:
                    return round(temperature, 1), f"Android-Akku: {battery_name}/{value_name}"
            except (OSError, ValueError):
                continue

    # Termux:API ist optional, liefert auf manchen Geräten aber den einzigen
    # freigegebenen Akku-/Telefonsensor.
    try:
        result = subprocess.run(
            ["termux-battery-status"],
            capture_output=True,
            text=True,
            timeout=1.0,
            check=False,
        )
        battery_data = json.loads(result.stdout or "{}")
        temperature = float(battery_data["temperature"])
        if 0.0 <= temperature <= 100.0:
            return round(temperature, 1), "Termux:API Akku"
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, json.JSONDecodeError):
        pass

    # Android selbst zeigt die Akkutemperatur über dumpsys in Zehntelgrad an.
    # Das funktioniert auch dann, wenn Termux:API nicht installiert ist.
    for command in (["dumpsys", "battery"], ["cmd", "thermalservice", "dump"]):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1.0,
                check=False,
            )
            output = result.stdout or ""
            battery_match = re.search(
                r"(?:temperature|mValue)\s*[:=]\s*([0-9]+(?:[.,][0-9]+)?)",
                output,
                re.IGNORECASE,
            )
            if battery_match:
                raw_value = float(battery_match.group(1).replace(",", "."))
                temperature = raw_value / 10.0 if raw_value > 100 else raw_value
                if 0.0 <= temperature <= 100.0:
                    return round(temperature, 1), f"Android: {' '.join(command)}"
        except (OSError, subprocess.SubprocessError, ValueError):
            continue

    return None, "Android gibt keinen Temperaturwert frei (Agent/Termux prüfen)"


def sys_monitor_worker():
    """Misst echte CPU-/RAM-/Netzwerkwerte des Telefons kontinuierlich."""
    global GLOBAL_CPU, GLOBAL_RAM, PHONE_METRICS_SOURCE, PHONE_METRICS_ERROR
    global GLOBAL_WIFI_DOWN_MBPS, GLOBAL_WIFI_UP_MBPS
    global WIFI_PREV_RX, WIFI_PREV_TX, WIFI_PREV_TIME
    global REMOTE_PHONE_METRICS_LAST_AT
    global PHONE_TEMPERATURE_C, PHONE_TEMPERATURE_SOURCE

    last_temperature_read_at = 0.0
    while True:
        time.sleep(1.0)
        remote_metrics_active = False
        with STATE_LOCK:
            # Falls ein optionaler Telefon-Agent Daten an diesen Server
            # sendet, werden diese nicht durch Werte des externen Dashboards
            # ersetzt. Nach einem Abbruch bleiben die letzten Heimwerte
            # sichtbar und werden als veraltet markiert.
            if REMOTE_PHONE_METRICS_LAST_AT > 0:
                remote_age = time.time() - REMOTE_PHONE_METRICS_LAST_AT
                if remote_age <= 5.0:
                    remote_metrics_active = True
                else:
                    PHONE_METRICS_ERROR = (
                        f"Telefon-Agent seit {int(remote_age)} s nicht erreichbar"
                    )

        if (
            not remote_metrics_active
            and time.monotonic() - last_temperature_read_at >= 10.0
        ):
            last_temperature_read_at = time.monotonic()
            temperature_c, temperature_source = read_phone_temperature()
            with STATE_LOCK:
                PHONE_TEMPERATURE_C = temperature_c
                PHONE_TEMPERATURE_SOURCE = temperature_source

        # Echte Gesamt-CPU des Android-Geräts lesen. Einige Android-/Termux-
        # Versionen geben den Gesamtzähler nicht frei; dafür wird weiter unten
        # ein geglätteter Verlauf als stabiler Fallback verwendet.
        if remote_metrics_active:
            cpu_value, cpu_source = None, None
            ram_value, ram_used_mb, ram_total_mb = None, None, None
        else:
            cpu_value, cpu_source = read_phone_cpu_percent()
            ram_value, ram_used_mb, ram_total_mb = read_phone_memory()

        # psutil bleibt als Fallback für Systeme ohne lesbares /proc erhalten.
        if ram_value is None:
            try:
                if psutil is not None:
                    memory = psutil.virtual_memory()
                    ram_value = round(float(memory.percent), 1)
                    ram_used_mb = round(memory.used / 1024 / 1024, 1)
                    ram_total_mb = round(memory.total / 1024 / 1024, 1)
            except (OSError, AttributeError, ValueError):
                pass

        # WLAN-Durchsatz: Delta der kumulierten Byte-Zähler seit der letzten
        # Messung, umgerechnet in Mbit/s (echte Zeitdifferenz statt
        # angenommener 1.0s, damit es auch bei kurzen Verzögerungen stimmt).
        now_ts = time.time()
        rx_bytes, tx_bytes = read_phone_wifi_bytes()
        if rx_bytes is None or tx_bytes is None:
            # Wenn Android/Termux keine Interface-Zähler freigibt, werden die
            # tatsächlich über diesen Server übertragenen Bytes verwendet.
            # Dadurch bleibt die Anzeige auch im Telefon-Agent-Modus live.
            with STATE_LOCK:
                rx_bytes = APPLICATION_RX_BYTES
                tx_bytes = APPLICATION_TX_BYTES
            WIFI_INTERFACES_SOURCE = "Server-Traffic (Fallback)"
        wifi_down_mbps = 0.0
        wifi_up_mbps = 0.0
        if rx_bytes is not None and tx_bytes is not None:
            if WIFI_PREV_RX is not None and WIFI_PREV_TIME is not None:
                dt = max(0.001, now_ts - WIFI_PREV_TIME)
                rx_delta = rx_bytes - WIFI_PREV_RX
                tx_delta = tx_bytes - WIFI_PREV_TX
                # Negative Deltas (z.B. nach WLAN-Reconnect/Zähler-Reset)
                # ignorieren statt falsche Werte zu zeigen.
                if rx_delta >= 0 and tx_delta >= 0:
                    wifi_down_mbps = round((rx_delta * 8) / dt / 1_000_000, 2)
                    wifi_up_mbps = round((tx_delta * 8) / dt / 1_000_000, 2)
            WIFI_PREV_RX = rx_bytes
            WIFI_PREV_TX = tx_bytes
            WIFI_PREV_TIME = now_ts
        else:
            WIFI_PREV_RX = None
            WIFI_PREV_TX = None
            WIFI_PREV_TIME = None

        if remote_metrics_active:
            with STATE_LOCK:
                GLOBAL_WIFI_DOWN_MBPS = wifi_down_mbps
                GLOBAL_WIFI_UP_MBPS = wifi_up_mbps
            continue

        cpu_is_estimated = cpu_value is None
        if cpu_is_estimated:
            cpu_value = estimate_phone_cpu_percent(wifi_down_mbps, wifi_up_mbps)
            cpu_source = "Telefonmonitor"
        else:
            CPU_SAMPLES.append(cpu_value)
            cpu_value = round(sum(CPU_SAMPLES) / len(CPU_SAMPLES), 1)

        with STATE_LOCK:
            if cpu_value is not None:
                GLOBAL_CPU = cpu_value
            if ram_value is not None:
                GLOBAL_RAM = ram_value
            GLOBAL_WIFI_DOWN_MBPS = wifi_down_mbps
            GLOBAL_WIFI_UP_MBPS = wifi_up_mbps

            if cpu_value is not None or ram_value is not None:
                PHONE_METRICS_SOURCE = cpu_source or "Android-Telefonmessung"
                PHONE_METRICS_ERROR = (
                    None
                    if cpu_value is not None
                    else "Android gibt keinen lesbaren Gesamt-CPU-Zähler frei."
                )
            else:
                PHONE_METRICS_SOURCE = "Telefonmonitor"
                PHONE_METRICS_ERROR = None

monitor_thread = threading.Thread(target=sys_monitor_worker, daemon=True)
monitor_thread.start()


def update_traffic_history(req_type):
    global LAST_SEC_TIMESTAMP, CURRENT_SEC_SUCCESS, CURRENT_SEC_BLOCKED, CURRENT_SEC_OVERLOAD
    now_sec = int(time.time())
    
    with STATE_LOCK:
        if now_sec - LAST_SEC_TIMESTAMP > 60:
            TRAFFIC_HISTORY.clear()
            TRAFFIC_HISTORY.extend([(0, 0, 0)] * 60)
            LAST_SEC_TIMESTAMP = now_sec
            CURRENT_SEC_SUCCESS = 0
            CURRENT_SEC_BLOCKED = 0
            CURRENT_SEC_OVERLOAD = 0
        else:
            while now_sec > LAST_SEC_TIMESTAMP:
                TRAFFIC_HISTORY.append((CURRENT_SEC_SUCCESS, CURRENT_SEC_BLOCKED, CURRENT_SEC_OVERLOAD))
                CURRENT_SEC_SUCCESS = 0
                CURRENT_SEC_BLOCKED = 0
                CURRENT_SEC_OVERLOAD = 0
                LAST_SEC_TIMESTAMP += 1

        if req_type == "success":
            CURRENT_SEC_SUCCESS += 1
        elif req_type == "blocked":
            CURRENT_SEC_BLOCKED += 1
        elif req_type == "overload":
            CURRENT_SEC_OVERLOAD += 1

def is_ip_vpn_or_proxy(ip):
    if ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return False

    now = time.time()
    with STATE_LOCK:
        if ip in VPN_CACHE:
            if now - VPN_CACHE[ip]["time"] < 600:
                return VPN_CACHE[ip]["is_vpn"]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=1.5) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success":
                is_proxy_or_vpn = bool(data.get("proxy", False) or data.get("hosting", False))
                with STATE_LOCK:
                    VPN_CACHE[ip] = {"is_vpn": is_proxy_or_vpn, "time": time.time()}
                return is_proxy_or_vpn
    except Exception:
        pass
    return False

def analyze_client_detailed(headers):
    ua_string = headers.get("User-Agent", "")
    ua = ua_string.lower()

    script_signatures = [
        "python", "requests", "urllib", "curl", "wget", "postman", "axios", "java/", "libwww", "httpclient", "perl", "ruby"
    ]
    is_known_script = any(sig in ua for sig in script_signatures)
    is_bot_keyword = (
        "bot" in ua
        or "crawler" in ua
        or "spider" in ua
        or "slurp" in ua
        or "ia_archiver" in ua
        or "headless" in ua
    )
    has_sec_headers = "sec-fetch-dest" in headers or "sec-ch-ua" in headers
    is_spoofed = (
        not is_known_script
        and not is_bot_keyword
        and not has_sec_headers
        and ("chrome" in ua or "safari" in ua)
        and "mobile" not in ua
    )

    if "chrome" in ua and "edge" not in ua and "opr" not in ua:
        browser = "Google Chrome"
    elif "firefox" in ua:
        browser = "Mozilla Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Apple Safari"
    elif "edge" in ua:
        browser = "Microsoft Edge"
    else:
        browser = "Bot / Skript"

    device = "Mobile" if ("mobile" in ua or "android" in ua or "iphone" in ua) else "Desktop"
    is_bot_or_script = is_known_script or is_bot_keyword or is_spoofed or not ua_string

    if is_bot_or_script:
        status_msg = f"🤖 Bot/Angriff erkannt {'(Getarnt)' if is_spoofed else ''}"
    else:
        status_msg = f"Erlaubt ({device} - {browser})"

    return browser, device, is_bot_or_script, status_msg

def is_client_allowed(headers):
    browser, device, is_bot_or_script, _ = analyze_client_detailed(headers)
    
    if device == "Desktop" and not ALLOW_DESKTOP:
        return False
    if device == "Mobile" and not ALLOW_MOBILE:
        return False
        
    if is_bot_or_script:
        return ALLOW_BOTS
        
    if browser == "Google Chrome" and not ALLOW_CHROME:
        return False
    if browser == "Mozilla Firefox" and not ALLOW_FIREFOX:
        return False
    if browser == "Apple Safari" and not ALLOW_SAFARI:
        return False
    if browser == "Microsoft Edge" and not ALLOW_EDGE:
        return False
    return True

MAX_TRACKED_USER_AGENTS = 200
MAX_TRACKED_ACTIVE_IPS = 3000
MAX_TRACKED_IP_REQUESTS = 5000
MAX_TRACKED_TEMP_BANS = 5000
MAX_TRACKED_VPN_CACHE = 2000


def cleanup_tracker_once(now=None):
    """Prune expired and excess request metadata to keep memory bounded."""
    now = time.time() if now is None else now
    with STATE_LOCK:
        expired = [
            ip for ip, data in ACTIVE_IP_TRACKER.items()
            if now - data.get("last_seen", 0) > 3600
        ]
        for ip in expired:
            del ACTIVE_IP_TRACKER[ip]
        if len(ACTIVE_IP_TRACKER) > MAX_TRACKED_ACTIVE_IPS:
            oldest = sorted(
                ACTIVE_IP_TRACKER,
                key=lambda ip: ACTIVE_IP_TRACKER[ip].get("last_seen", 0),
            )[:len(ACTIVE_IP_TRACKER) - MAX_TRACKED_ACTIVE_IPS]
            for ip in oldest:
                del ACTIVE_IP_TRACKER[ip]

        # Remove expired temporary bans even if the client never reconnects.
        expired_bans = [
            ip for ip, expiry in TEMPORARY_BANS.items()
            if expiry <= now
        ]
        for ip in expired_bans:
            del TEMPORARY_BANS[ip]
        if len(TEMPORARY_BANS) > MAX_TRACKED_TEMP_BANS:
            earliest_expiring = sorted(
                TEMPORARY_BANS,
                key=TEMPORARY_BANS.get,
            )[:len(TEMPORARY_BANS) - MAX_TRACKED_TEMP_BANS]
            for ip in earliest_expiring:
                del TEMPORARY_BANS[ip]

        stale_ip_counts = [
            ip for ip, timestamps in ip_request_counts.items()
            if not timestamps or now - timestamps[-1] > 60
        ]
        for ip in stale_ip_counts:
            del ip_request_counts[ip]
        if len(ip_request_counts) > MAX_TRACKED_IP_REQUESTS:
            least_recent_ip_counts = sorted(
                ip_request_counts,
                key=lambda ip: ip_request_counts[ip][-1] if ip_request_counts[ip] else 0,
            )[:len(ip_request_counts) - MAX_TRACKED_IP_REQUESTS]
            for ip in least_recent_ip_counts:
                del ip_request_counts[ip]

        stale_vpn = [
            ip for ip, data in VPN_CACHE.items()
            if now - data.get("time", 0) > 600
        ]
        for ip in stale_vpn:
            del VPN_CACHE[ip]
        if len(VPN_CACHE) > MAX_TRACKED_VPN_CACHE:
            oldest_vpn = sorted(
                VPN_CACHE,
                key=lambda ip: VPN_CACHE[ip].get("time", 0),
            )[:len(VPN_CACHE) - MAX_TRACKED_VPN_CACHE]
            for ip in oldest_vpn:
                del VPN_CACHE[ip]

        if len(user_agent_stats) > MAX_TRACKED_USER_AGENTS:
            top_agents = sorted(
                user_agent_stats.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:MAX_TRACKED_USER_AGENTS]
            user_agent_stats.clear()
            user_agent_stats.update(top_agents)


def cleanup_tracker():
    while True:
        time.sleep(60)
        cleanup_tracker_once()

cleanup_thread = threading.Thread(target=cleanup_tracker, daemon=True)
cleanup_thread.start()

BG_ANIMATION_JS = '''<div class="plexusBg" aria-hidden="true">
  <canvas id="plexusCanvas"></canvas>
  <div class="plexusScan"></div>
</div>
<style>
.plexusBg{position:fixed;inset:0;z-index:-1;overflow:hidden;background:radial-gradient(ellipse at 50% 0%,#170a2e 0%,#05030c 55%,#020005 100%);pointer-events:none;}
.plexusBg canvas{position:absolute;inset:0;width:100%;height:100%;display:block;}
.plexusScan{position:absolute;left:0;right:0;height:140px;background:linear-gradient(180deg,rgba(192,132,252,0) 0%,rgba(192,132,252,0.12) 50%,rgba(192,132,252,0) 100%);animation:plexusScanMove 7s linear infinite;mix-blend-mode:screen;}
@keyframes plexusScanMove{0%{top:-140px;}100%{top:100%;}}
@media (prefers-reduced-motion: reduce){.plexusScan{animation:none;display:none;}}
</style>
<script>
(function(){
  try{
    var canvas=document.getElementById('plexusCanvas');
    if(!canvas||!canvas.getContext) return;
    var ctx=canvas.getContext('2d');
    var reduceMotion=window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var W=0,H=0,DPR=Math.min(window.devicePixelRatio||1,2);
    var PALETTE=['#c084fc','#a855f7','#38bdf8','#f472b6','#34d399'];
    var nodes=[];
    function resize(){
      W=window.innerWidth; H=window.innerHeight;
      canvas.width=Math.floor(W*DPR); canvas.height=Math.floor(H*DPR);
      canvas.style.width=W+'px'; canvas.style.height=H+'px';
      ctx.setTransform(DPR,0,0,DPR,0,0);
      var target=Math.max(28,Math.min(70,Math.round((W*H)/26000)));
      nodes=[];
      for(var i=0;i<target;i++){
        nodes.push({
          x:Math.random()*W, y:Math.random()*H,
          vx:(Math.random()-0.5)*0.35, vy:(Math.random()-0.5)*0.35,
          r:1.2+Math.random()*1.8,
          c:PALETTE[i%PALETTE.length],
          pulse:Math.random()*Math.PI*2
        });
      }
    }
    function step(t){
      ctx.clearRect(0,0,W,H);
      var linkDist=Math.min(150,W/6);
      for(var i=0;i<nodes.length;i++){
        var n=nodes[i];
        n.x+=n.vx; n.y+=n.vy; n.pulse+=0.015;
        if(n.x<0||n.x>W) n.vx*=-1;
        if(n.y<0||n.y>H) n.vy*=-1;
        n.x=Math.max(0,Math.min(W,n.x));
        n.y=Math.max(0,Math.min(H,n.y));
      }
      for(var i=0;i<nodes.length;i++){
        for(var j=i+1;j<nodes.length;j++){
          var a=nodes[i], b=nodes[j];
          var dx=a.x-b.x, dy=a.y-b.y;
          var dist=Math.sqrt(dx*dx+dy*dy);
          if(dist<linkDist){
            var alpha=(1-dist/linkDist)*0.35;
            ctx.strokeStyle='rgba(168,120,255,'+alpha.toFixed(3)+')';
            ctx.lineWidth=1;
            ctx.beginPath();
            ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y);
            ctx.stroke();
          }
        }
      }
      for(var i=0;i<nodes.length;i++){
        var n=nodes[i];
        var glow=1+Math.sin(n.pulse)*0.4;
        ctx.beginPath();
        ctx.fillStyle=n.c;
        ctx.shadowColor=n.c;
        ctx.shadowBlur=10*glow;
        ctx.globalAlpha=0.85;
        ctx.arc(n.x,n.y,n.r*glow,0,Math.PI*2);
        ctx.fill();
      }
      ctx.shadowBlur=0; ctx.globalAlpha=1;
      if(!reduceMotion) requestAnimationFrame(step);
    }
    window.addEventListener('resize',resize,{passive:true});
    resize();
    requestAnimationFrame(step);
    if(reduceMotion) step(0);
  }catch(e){ /* Hintergrund-Animation ist rein dekorativ */ }
})();
</script>'''

PUBLIC_HTML = '''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Status</title>
    <style>
        :root {
            --bg: #030008;
            --card-bg: rgba(15, 10, 28, 0.75);
            --border: rgba(255, 255, 255, 0.08);
            --text: #f8fafc;
            --text-muted: #8b92b2;
            --primary: #c084fc;
            --success: #34d399;
            --danger: #f87171;
            --warning: #fbbf24;
        }
        body { 
            background: var(--bg); 
            color: var(--text); 
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            margin: 0; 
            padding: 24px; 
            display: flex; 
            flex-direction: column; 
            align-items: center; 
            min-height: 100vh; 
            box-sizing: border-box; 
            overflow-x: hidden;
        }
        .container { width: 100%; max-width: 580px; margin-top: 15px; }
        
        .top-mini-banner {
            position: fixed;
            top: 16px; right: 16px;
            background: rgba(28, 18, 48, 0.95);
            border: 1px solid rgba(192, 132, 252, 0.5);
            backdrop-filter: blur(10px);
            padding: 8px 16px;
            border-radius: 30px;
            z-index: 1000;
            font-size: 13px;
            font-weight: 600;
            color: var(--primary);
            box-shadow: 0 0 20px rgba(192, 132, 252, 0.3);
            cursor: pointer;
            text-decoration: none;
            transition: transform 0.2s, box-shadow 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .top-mini-banner:hover {
            transform: translateY(-1px);
            box-shadow: 0 0 25px rgba(192, 132, 252, 0.5);
        }

        .card { 
            background: var(--card-bg); 
            backdrop-filter: blur(20px); 
            -webkit-backdrop-filter: blur(20px); 
            border: 1px solid var(--border); 
            padding: 32px; 
            border-radius: 24px; 
            box-shadow: 0 20px 50px -15px rgba(0, 0, 0, 0.8), 0 0 30px rgba(168, 85, 247, 0.1); 
            position: relative;
            overflow: hidden;
            animation: floatIn 0.8s cubic-bezier(0.16, 1, 0.3, 1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 25px 60px -12px rgba(0, 0, 0, 0.9), 0 0 40px rgba(168, 85, 247, 0.2);
        }
        @keyframes floatIn {
            from { opacity: 0; transform: translateY(20px) scale(0.98); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .header-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; }
        h1 { font-size: 18px; margin: 0; color: var(--text); font-weight: 600; letter-spacing: -0.01em; }
        
        .status-pill { 
            display: inline-flex; 
            align-items: center; gap: 8px; 
            background: rgba(52, 211, 153, 0.08); 
            border: 1px solid rgba(52, 211, 153, 0.2); 
            color: var(--success); 
            padding: 6px 14px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: 500; transition: all 0.3s ease;
            box-shadow: 0 0 15px rgba(52, 211, 153, 0.1);
        }
        .status-pill.offline {
            background: rgba(248, 113, 113, 0.08);
            border-color: rgba(248, 113, 113, 0.2);
            color: var(--danger);
            box-shadow: 0 0 15px rgba(248, 113, 113, 0.1);
        }
        .status-dot { 
            width: 7px; 
            height: 7px; 
            background: var(--success); 
            border-radius: 50%; 
            display: inline-block; 
            animation: pulseGlow 2s infinite ease-in-out;
        }
        .status-pill.offline .status-dot {
            background: var(--danger);
            animation: pulseRed 1.5s infinite ease-in-out;
        }
        @keyframes pulseGlow {
            0% { transform: scale(0.95); opacity: 0.8; box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.4); }
            70% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 0 6px rgba(52, 211, 153, 0); }
            100% { transform: scale(0.95); opacity: 0.8; box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); }
        }
        @keyframes pulseRed {
            0% { opacity: 1; }
            50% { opacity: 0.3; }
            100% { opacity: 1; }
        }
        
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 24px; }
        .stat-box { 
            background: rgba(255, 255, 255, 0.02); 
            border: 1px solid var(--border); 
            padding: 16px 8px; 
            border-radius: 16px; 
            text-align: center; 
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .stat-box:hover {
            background: rgba(255, 255, 255, 0.04);
            border-color: rgba(255, 255, 255, 0.12);
            transform: translateY(-2px);
        }
        .stat-box .val { font-size: 16px; font-weight: 700; color: var(--text); margin-top: 6px; font-variant-numeric: tabular-nums; transition: color 0.3s; }
        .stat-box .lbl { font-size: 10px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }

        .chart-title { font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 6px; }
        .chart-title::before { content: ''; display: inline-block; width: 6px; height: 6px; background: var(--primary); border-radius: 50%; }
        
        .bars-container { display: flex; flex-direction: column; gap: 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border); border-radius: 16px; padding: 18px; }
        .bar-row { display: flex; align-items: center; gap: 12px; font-size: 12px; }
        .bar-label { width: 75px; color: var(--text-muted); font-weight: 500; }
        .bar-track { flex: 1; background: rgba(0, 0, 0, 0.4); height: 8px; border-radius: 4px; overflow: hidden; border: 1px solid rgba(255, 255, 255, 0.03); position: relative; }
        .bar-fill { 
            height: 100%; 
            width: 0%; 
            border-radius: 4px; 
            transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1); 
            position: relative;
        }
        .bar-fill::after {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(90deg, rgba(255,255,255,0) 0%, rgba(255,255,255,0.3) 50%, rgba(255,255,255,0) 100%);
            animation: shimmer 2s infinite linear;
        }
        @keyframes shimmer {
            from { transform: translateX(-100%); }
            to { transform: translateX(100%); }
        }
        .bar-value { width: 35px; text-align: right; font-family: ui-monospace, monospace; font-weight: 600; font-size: 12px; color: var(--text); }
        .request-chart {
            margin-top: 24px;
            padding: 16px 14px 12px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 16px;
            position: relative;
        }
        .request-chart-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 10px;
        }
        .request-chart-title {
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }
        .request-chart-title::before {
            content: '';
            display: inline-block;
            width: 6px;
            height: 6px;
            margin: 0 6px 1px 0;
            background: var(--primary);
            border-radius: 50%;
        }
        .request-chart-legend {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--text-muted);
            font-size: 10px;
            white-space: nowrap;
        }
        .request-chart-legend::before {
            content: '';
            width: 18px;
            height: 2px;
            background: #94a3b8;
            box-shadow: 0 0 8px rgba(148, 163, 184, 0.45);
        }
        #request-history-canvas {
            display: block;
            width: 100%;
            height: 170px;
            cursor: crosshair;
            touch-action: none;
            user-select: none;
        }
        .request-chart-tooltip {
            position: absolute;
            display: none;
            pointer-events: none;
            padding: 7px 9px;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 8px;
            background: rgba(8, 8, 18, 0.94);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
            color: var(--text);
            font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
            max-width: calc(100% - 16px);
            overflow-wrap: anywhere;
            z-index: 2;
        }
        @media (max-width: 480px) {
            .request-chart-header { align-items: flex-start; flex-direction: column; gap: 5px; }
            #request-history-canvas { height: 145px; }
        }
        .media-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
        .media-item { min-width: 0; margin: 0; padding: 10px; background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border); border-radius: 14px; }
        .media-item img, .media-item video { display: block; width: 100%; height: 220px; object-fit: contain; background: #050505; border-radius: 10px; }
        .media-item figcaption { margin-top: 8px; color: var(--text-muted); font-size: 12px; overflow-wrap: anywhere; }
        .download-card { display: flex; flex-direction: column; align-items: center; justify-content: center; width: 100%; height: 220px; text-decoration: none; color: var(--text); background: linear-gradient(145deg, rgba(59,130,246,0.15), rgba(16,185,129,0.12)); border: 1px dashed var(--border); border-radius: 10px; transition: transform 0.15s ease, background 0.15s ease; }
        .download-card:hover { transform: translateY(-2px); background: linear-gradient(145deg, rgba(59,130,246,0.28), rgba(16,185,129,0.22)); }
        .download-icon { font-size: 48px; line-height: 1; margin-bottom: 10px; }
        .download-label { font-size: 14px; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; color: var(--success); }
        .media-empty { color: var(--text-muted); font-size: 13px; line-height: 1.6; }
    </style>
</head>
<body>
    __BG_ANIMATION__
    
    <a class="top-mini-banner" href="/live-stats">
        <span>⚡ Live-Stats</span>
    </a>

    <div class="container">
        <div class="card">
            <div class="header-row">
                <h1>System Status</h1>
                <div class="status-pill" id="status-pill"><span class="status-dot"></span><span id="status-text">Operational</span></div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box"><div class="lbl">Total Requests</div><div class="val" id="total-req">__TOTAL_REQ__</div></div>
                <div class="stat-box"><div class="lbl">Live RPS</div><div class="val" id="current-rps" style="color:var(--success);">0</div></div>
                <div class="stat-box"><div class="lbl">Blocked RPS</div><div class="val" id="blocked-rps" style="color:var(--danger);">0</div></div>
            </div>

            <div class="chart-title">Traffic (Last Second)</div>
            
            <div class="bars-container">
                <div class="bar-row">
                    <div class="bar-label">Success</div>
                    <div class="bar-track"><div class="bar-fill" id="fill-success" style="background: linear-gradient(90deg, #10b981, #34d399);"></div></div>
                    <div class="bar-value" id="val-success">0</div>
                </div>
                <div class="bar-row">
                    <div class="bar-label">Blocked</div>
                    <div class="bar-track"><div class="bar-fill" id="fill-blocked" style="background: linear-gradient(90deg, #ef4444, #f87171);"></div></div>
                    <div class="bar-value" id="val-blocked">0</div>
                </div>
                <div class="bar-row">
                    <div class="bar-label">Overload</div>
                    <div class="bar-track"><div class="bar-fill" id="fill-overload" style="background: linear-gradient(90deg, #d97706, #fbbf24);"></div></div>
                    <div class="bar-value" id="val-overload">0</div>
                </div>
            </div>

            <div class="request-chart">
                <div class="request-chart-header">
                    <div class="request-chart-title">Anfragenverlauf (letzte 60 Sekunden)</div>
                    <div class="request-chart-legend">Alle Anfragen</div>
                </div>
                <canvas id="request-history-canvas" aria-label="Verlauf aller Anfragen"></canvas>
                <div class="request-chart-tooltip" id="request-chart-tooltip"></div>
            </div>
        </div>

        <div class="card" id="media-card">
            <div class="header-row">
                <h1>Bilder, Videos &amp; Downloads vom Server</h1>
                <span class="status-pill">lokal geladen</span>
            </div>
            <p class="media-empty" id="media-empty">Medien werden vom Server geladen ...</p>
            <div class="media-grid" id="media-gallery"></div>
        </div>
    </div>

    <script>
        function loadMediaGallery() {
            const gallery = document.getElementById('media-gallery');
            const emptyMessage = document.getElementById('media-empty');

            fetch('/api/media', { cache: 'no-store' })
                .then(response => {
                    if (!response.ok) throw new Error();
                    return response.json();
                })
                .then(items => {
                    gallery.replaceChildren();
                    const mediaCard = document.getElementById('media-card');
                    if (!Array.isArray(items) || items.length === 0) {
                        // Kein Download, kein Bild, kein Video vorhanden -> ganze Karte entfernen.
                        if (mediaCard) mediaCard.remove();
                        return;
                    }

                    if (mediaCard) mediaCard.hidden = false;
                    emptyMessage.hidden = true;
                    items.forEach(item => {
                        const figure = document.createElement('figure');
                        figure.className = 'media-item';

                        const mediaUrl = '/media/' + encodeURIComponent(item.name);
                        if (item.type === 'file') {
                            const link = document.createElement('a');
                            link.href = mediaUrl;
                            link.download = item.name;
                            link.className = 'download-card';
                            link.innerHTML = '<div class="download-icon">⬇</div><div class="download-label">Download</div>';
                            const caption = document.createElement('figcaption');
                            caption.textContent = item.name;
                            figure.append(link, caption);
                        } else {
                            let player;
                            if (item.type === 'image') {
                                player = document.createElement('img');
                                player.alt = item.name;
                                player.loading = 'lazy';
                                player.decoding = 'async';
                            } else {
                                player = document.createElement('video');
                                player.controls = true;
                                player.preload = 'none';
                                player.playsInline = true;
                            }
                            player.src = mediaUrl;
                            const caption = document.createElement('figcaption');
                            caption.textContent = item.name;
                            figure.append(player, caption);
                        }
                        gallery.appendChild(figure);
                    });
                })
                .catch(() => {
                    // Server nicht erreichbar oder Route nicht vorhanden -> Karte vorsorglich ausblenden.
                    const mediaCard = document.getElementById('media-card');
                    if (mediaCard) mediaCard.hidden = true;
                });
        }

        function setOfflineState() {
            document.getElementById('status-pill').className = 'status-pill offline';
            document.getElementById('status-text').innerText = 'Offline';
        }

        function setOnlineState() {
            document.getElementById('status-pill').className = 'status-pill';
            document.getElementById('status-text').innerText = 'Operational';
        }

        const requestHistoryCanvas = document.getElementById('request-history-canvas');
        const requestHistoryContext = requestHistoryCanvas.getContext('2d');
        const requestChartTooltip = document.getElementById('request-chart-tooltip');
        let requestHistory = [];
        let requestSelectedIndex = null;

        function resizeRequestChart() {
            const ratio = Math.min(window.devicePixelRatio || 1, 2);
            const rect = requestHistoryCanvas.getBoundingClientRect();
            requestHistoryCanvas.width = Math.max(1, Math.floor(rect.width * ratio));
            requestHistoryCanvas.height = Math.max(1, Math.floor(rect.height * ratio));
            requestHistoryContext.setTransform(ratio, 0, 0, ratio, 0, 0);
            drawRequestChart();
        }

        function requestSampleValues(history) {
            return (Array.isArray(history) ? history : []).map(sample => {
                const values = Array.isArray(sample) ? sample : [];
                return {
                    total: Number(values[0] || 0) + Number(values[1] || 0) + Number(values[2] || 0),
                    success: Number(values[0] || 0),
                    blocked: Number(values[1] || 0),
                    overload: Number(values[2] || 0)
                };
            });
        }

        function drawRequestChart() {
            if (!requestHistoryCanvas || !requestHistoryContext) return;
            const rect = requestHistoryCanvas.getBoundingClientRect();
            const width = rect.width;
            const height = rect.height;
            if (!width || !height) return;

            requestHistoryContext.clearRect(0, 0, width, height);
            const samples = requestSampleValues(requestHistory);
            const values = samples.map(sample => sample.total);
            const maxValue = Math.max(1, ...values);
            const padding = { top: 10, right: 8, bottom: 18, left: 26 };
            const chartWidth = Math.max(1, width - padding.left - padding.right);
            const chartHeight = Math.max(1, height - padding.top - padding.bottom);
            const pointStep = chartWidth / Math.max(1, values.length - 1);

            requestHistoryContext.font = '10px system-ui, sans-serif';
            requestHistoryContext.textBaseline = 'middle';
            requestHistoryContext.lineWidth = 1;
            requestHistoryContext.strokeStyle = 'rgba(255, 255, 255, 0.07)';
            requestHistoryContext.fillStyle = '#68708e';

            for (let i = 0; i <= 4; i++) {
                const y = padding.top + chartHeight - (chartHeight * i / 4);
                requestHistoryContext.beginPath();
                requestHistoryContext.moveTo(padding.left, y);
                requestHistoryContext.lineTo(width - padding.right, y);
                requestHistoryContext.stroke();
                const label = Math.round(maxValue * i / 4);
                requestHistoryContext.textAlign = 'right';
                requestHistoryContext.fillText(label, padding.left - 6, y);
            }

            requestHistoryContext.textBaseline = 'alphabetic';
            requestHistoryContext.textAlign = 'left';
            requestHistoryContext.fillText('60s', padding.left, height - 2);
            requestHistoryContext.textAlign = 'right';
            requestHistoryContext.fillText('jetzt', width - padding.right, height - 2);

            if (!values.length) return;
            const points = values.map((value, index) => ({
                x: padding.left + index * pointStep,
                y: padding.top + chartHeight - (value / maxValue) * chartHeight
            }));

            requestHistoryContext.beginPath();
            points.forEach((point, index) => {
                if (index === 0) requestHistoryContext.moveTo(point.x, point.y);
                else requestHistoryContext.lineTo(point.x, point.y);
            });
            requestHistoryContext.strokeStyle = '#94a3b8';
            requestHistoryContext.lineWidth = 2;
            requestHistoryContext.shadowColor = 'rgba(148, 163, 184, 0.42)';
            requestHistoryContext.shadowBlur = 8;
            requestHistoryContext.stroke();
            requestHistoryContext.shadowBlur = 0;

            if (requestSelectedIndex !== null && points[requestSelectedIndex]) {
                const selectedPoint = points[requestSelectedIndex];
                requestHistoryContext.beginPath();
                requestHistoryContext.moveTo(selectedPoint.x, padding.top);
                requestHistoryContext.lineTo(selectedPoint.x, padding.top + chartHeight);
                requestHistoryContext.strokeStyle = 'rgba(192, 132, 252, 0.72)';
                requestHistoryContext.lineWidth = 1;
                requestHistoryContext.setLineDash([4, 4]);
                requestHistoryContext.stroke();
                requestHistoryContext.setLineDash([]);

                requestHistoryContext.beginPath();
                requestHistoryContext.arc(selectedPoint.x, selectedPoint.y, 6, 0, Math.PI * 2);
                requestHistoryContext.fillStyle = 'rgba(192, 132, 252, 0.22)';
                requestHistoryContext.fill();
                requestHistoryContext.beginPath();
                requestHistoryContext.arc(selectedPoint.x, selectedPoint.y, 3.5, 0, Math.PI * 2);
                requestHistoryContext.fillStyle = '#c084fc';
                requestHistoryContext.shadowColor = '#c084fc';
                requestHistoryContext.shadowBlur = 10;
                requestHistoryContext.fill();
                requestHistoryContext.shadowBlur = 0;
            }

        }

        function showRequestTooltip(event) {
            if (!requestHistory.length) return;
            const rect = requestHistoryCanvas.getBoundingClientRect();
            let clientX = event.clientX;
            if (typeof clientX !== 'number' && event.touches && event.touches.length) {
                clientX = event.touches[0].clientX;
            }
            if (typeof clientX !== 'number') return;
            const padding = { left: 26, right: 8, top: 10, bottom: 18 };
            const chartWidth = Math.max(1, rect.width - padding.left - padding.right);
            const x = Math.max(padding.left, Math.min(rect.width - padding.right, clientX - rect.left));
            const samples = requestSampleValues(requestHistory);
            const index = Math.max(0, Math.min(
                samples.length - 1,
                Math.round(((x - padding.left) / chartWidth) * (samples.length - 1))
            ));
            const sample = samples[index];
            requestSelectedIndex = index;
            drawRequestChart();
            requestChartTooltip.innerHTML =
                '<strong>Alle Anfragen: ' + sample.total + '</strong><br>' +
                '<span style="color:#34d399">Erlaubt: ' + sample.success + '</span> · ' +
                '<span style="color:#f87171">Geblockt: ' + sample.blocked + '</span> · ' +
                '<span style="color:#fbbf24">Überlastung: ' + sample.overload + '</span>';
            requestChartTooltip.style.display = 'block';
            const tooltipWidth = requestChartTooltip.offsetWidth || 170;
            const tooltipHeight = requestChartTooltip.offsetHeight || 42;
            const maxValue = Math.max(1, ...samples.map(entry => entry.total));
            const chartHeight = Math.max(1, rect.height - padding.top - padding.bottom);
            const selectedPointX = padding.left + ((index / Math.max(1, samples.length - 1)) * chartWidth);
            const selectedPointY = padding.top + chartHeight - (sample.total / maxValue) * chartHeight;
            const containerRect = requestHistoryCanvas.parentElement.getBoundingClientRect();
            const pointXInContainer = rect.left - containerRect.left + selectedPointX;
            const pointYInContainer = rect.top - containerRect.top + selectedPointY;
            const left = Math.max(8, Math.min(containerRect.width - tooltipWidth - 8, pointXInContainer + 10));
            let top = pointYInContainer - tooltipHeight - 10;
            if (top < 8) top = pointYInContainer + 10;
            top = Math.max(8, Math.min(containerRect.height - tooltipHeight - 8, top));
            requestChartTooltip.style.left = left + 'px';
            requestChartTooltip.style.top = top + 'px';
        }

        function hideRequestTooltip() {
            requestSelectedIndex = null;
            drawRequestChart();
            requestChartTooltip.style.display = 'none';
        }

        window.addEventListener('resize', resizeRequestChart, { passive: true });
        if (window.PointerEvent) {
            requestHistoryCanvas.addEventListener('pointermove', showRequestTooltip, { passive: true });
            requestHistoryCanvas.addEventListener('pointerdown', showRequestTooltip, { passive: true });
            requestHistoryCanvas.addEventListener('pointerleave', hideRequestTooltip, { passive: true });
            requestHistoryCanvas.addEventListener('pointercancel', hideRequestTooltip, { passive: true });
        } else {
            requestHistoryCanvas.addEventListener('mousemove', showRequestTooltip);
            requestHistoryCanvas.addEventListener('mouseleave', hideRequestTooltip);
            requestHistoryCanvas.addEventListener('click', showRequestTooltip);
            requestHistoryCanvas.addEventListener('touchstart', showRequestTooltip, { passive: true });
            requestHistoryCanvas.addEventListener('touchcancel', hideRequestTooltip, { passive: true });
        }
        resizeRequestChart();

        function updateStats() {
            return fetch('/api/stats', { mode: 'cors', cache: 'no-store' })
                .then(res => {
                    if (!res.ok) throw new Error();
                    return res.json();
                })
                .then(data => {
                    document.getElementById('total-req').innerText = data.total;
                    document.getElementById('current-rps').innerText = data.rps;
                    document.getElementById('blocked-rps').innerText = data.blocked_rps !== undefined ? data.blocked_rps : 0;

                    if (data.history && Array.isArray(data.history) && data.history.length > 0) {
                        requestHistory = data.history;
                        drawRequestChart();
                        const latest = data.history[data.history.length - 1];
                        const succ = (latest && latest[0]) ? latest[0] : 0;
                        const block = (latest && latest[1]) ? latest[1] : 0;
                        const over = (latest && latest[2]) ? latest[2] : 0;

                        document.getElementById('val-success').innerText = succ;
                        document.getElementById('val-blocked').innerText = block;
                        document.getElementById('val-overload').innerText = over;

                        const maxScale = Math.max(20, succ, block, over);

                        document.getElementById('fill-success').style.width = Math.min(100, (succ / maxScale) * 100) + '%';
                        document.getElementById('fill-blocked').style.width = Math.min(100, (block / maxScale) * 100) + '%';
                        document.getElementById('fill-overload').style.width = Math.min(100, (over / maxScale) * 100) + '%';
                    }
                    setOnlineState();
                })
                .catch(err => {
                    setOfflineState();
                });
        }
        
        // Der Homescreen bleibt live: Stats und Anfrage-Diagramm werden
        // automatisch aktualisiert. Die 503-Seite besitzt bewusst keinen
        // Reload-Timer und bleibt statisch.
        setInterval(updateStats, 500);
        updateStats();
        loadMediaGallery();
    </script>
</body>
</html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

LIVE_STATS_HTML = '''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Telemetrie</title>
    <style>
        :root {
            --bg: #030008;
            --card-bg: rgba(15, 10, 28, 0.75);
            --border: rgba(255, 255, 255, 0.08);
            --text: #f8fafc;
            --text-muted: #8b92b2;
            --primary: #c084fc;
            --success: #34d399;
            --danger: #f87171;
            --warning: #fbbf24;
        }
        body { 
            background: var(--bg); 
            color: var(--text); 
            font-family: system-ui, -apple-system, sans-serif; 
            margin: 0; 
            padding: 24px; 
            display: flex; 
            flex-direction: column; 
            align-items: center; 
            min-height: 100vh; 
            box-sizing: border-box; 
        }
        .container { width: 100%; max-width: 620px; margin-top: 15px; }
        .card { 
            background: var(--card-bg); 
            backdrop-filter: blur(20px); 
            border: 1px solid var(--border); 
            padding: 32px; 
            border-radius: 24px; 
            box-shadow: 0 20px 50px -15px rgba(0, 0, 0, 0.8), 0 0 30px rgba(168, 85, 247, 0.1); 
            margin-bottom: 20px;
        }
        .header-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
        h1 { font-size: 18px; margin: 0; color: var(--text); font-weight: 600; }
        .back-btn { background: rgba(192, 132, 252, 0.1); border: 1px solid rgba(192, 132, 252, 0.3); color: var(--primary); padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; text-decoration: none; transition: all 0.2s; }
        .back-btn:hover { background: rgba(192, 132, 252, 0.2); }
        
        .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 24px; }
        .stat-box { 
            background: rgba(255, 255, 255, 0.02); 
            border: 1px solid var(--border); 
            padding: 20px 12px; 
            border-radius: 16px; 
            text-align: center; 
        }
        .stat-box .val { font-size: 22px; font-weight: 700; color: var(--text); margin-top: 8px; font-variant-numeric: tabular-nums; }
        .stat-box .lbl { font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }

        .chart-container {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px;
            margin-top: 16px;
            position: relative;
        }
        .chart-title { font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
        canvas.line-chart {
            width: 100%;
            height: 140px;
            display: block;
        }
        .chart-tooltip {
            display: none;
            position: absolute;
            z-index: 10;
            pointer-events: none;
            min-width: 125px;
            padding: 8px 10px;
            border: 1px solid rgba(192, 132, 252, 0.45);
            border-radius: 10px;
            background: rgba(8, 5, 18, 0.96);
            color: var(--text);
            font-size: 11px;
            line-height: 1.5;
            box-shadow: 0 8px 24px rgba(0,0,0,.45);
            white-space: nowrap;
        }
    </style>
</head>
<body>
    __BG_ANIMATION__
    <div class="container">
        <div class="card">
            <div class="header-row">
                <h1>Live 60-Sekunden Telemetrie</h1>
                <a href="/" class="back-btn">← Zurück</a>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box"><div class="lbl">Live Ping</div><div class="val" id="live-ping" style="color:var(--success);">-- ms</div></div>
                <div class="stat-box"><div class="lbl">Packet Loss</div><div class="val" id="live-loss" style="color:var(--success);">0.0%</div></div>
            </div>

            <div class="chart-container">
                 <div class="chart-title">Ping + Paketverlust (letzte 60 Sekunden)</div>
                <canvas id="historyCanvas" class="line-chart"></canvas>
                 <div id="history-tooltip" class="chart-tooltip"></div>
            </div>
        </div>

        <div class="card">
            <div class="header-row">
                <h1>Live CPU / RAM / Temperatur (Handy)</h1>
                <a href="/" class="back-btn">← Zurück</a>
            </div>
            
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
                <div class="stat-box"><div class="lbl">CPU-Auslastung (Handy)</div><div class="val" id="live-cpu" style="color:var(--success);">warte ...</div></div>
                <div class="stat-box"><div class="lbl">RAM Auslastung (Telefon)</div><div class="val" id="live-ram" style="color:var(--success);">warte ...</div></div>
                <div class="stat-box"><div class="lbl">Temperatur (Handy)</div><div class="val" id="live-temperature" style="color:#fbbf24;">warte ...</div></div>
            </div>

            <div class="chart-container">
                <div class="chart-title">CPU + RAM Verlauf (letzte 60 Sekunden)</div>
                <canvas id="cpu-ram-chart" height="130"></canvas>
                 <div id="cpu-ram-tooltip" class="chart-tooltip"></div>
            </div>
        </div>

        <div class="card">
            <div class="header-row">
                <h1>Live WLAN-/Netzwerk-Durchsatz</h1>
                <a href="/" class="back-btn">← Zurück</a>
            </div>

            <div class="stats-grid" style="grid-template-columns: 1fr 1fr;">
                <div class="stat-box"><div class="lbl">Download</div><div class="val" id="live-wifi-down" style="color:var(--success);">warte ...</div></div>
                <div class="stat-box"><div class="lbl">Upload</div><div class="val" id="live-wifi-up" style="color:var(--danger);">warte ...</div></div>
            </div>
            <div id="wifi-source" style="color:var(--muted);font-size:0.8rem;margin-top:8px;">Schnittstelle wird gesucht ...</div>

            <div class="chart-container">
                <div class="chart-title">WLAN/Netzwerk Down/Up in Mbit/s (letzte 60 Sekunden)</div>
                <canvas id="wifi-chart" height="130"></canvas>
                 <div id="wifi-tooltip" class="chart-tooltip"></div>
            </div>
        </div>
    </div>

    <script>
        let totalPings = 0;
        let failedPings = 0;
        const canvas = document.getElementById('historyCanvas');
        const ctx = canvas.getContext('2d');
        let pingSamples = [];

        function resizeCanvas() {
            canvas.width = canvas.parentElement.clientWidth - 32;
            canvas.height = 140;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        function calculateLossAt(index) {
            const start = Math.max(0, index - 59);
            const windowSamples = pingSamples.slice(start, index + 1);
            if (!windowSamples.length) return 0;
            return windowSamples.filter(sample => !sample.ok).length / windowSamples.length * 100;
        }

        function drawChart(historyData) {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            if (!pingSamples.length) return;

            const maxPing = Math.max(50, ...pingSamples.map(sample => sample.ms || 0));
            const stepX = canvas.width / (pingSamples.length - 1 || 1);

            function drawLine(values, color, maxValue) {
                ctx.beginPath();
                ctx.strokeStyle = color;
                ctx.lineWidth = 2;
                for (let i = 0; i < values.length; i++) {
                    const val = values[i] || 0;
                    const x = i * stepX;
                    const y = canvas.height - (val / maxValue) * (canvas.height - 20) - 10;
                    if (i === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                }
                ctx.stroke();
            }

            ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
            ctx.lineWidth = 1;
            for(let i=0; i<4; i++) {
                let y = (canvas.height / 4) * i;
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(canvas.width, y);
                ctx.stroke();
            }

            drawLine(pingSamples.map(sample => sample.ms || 0), '#34d399', maxPing);
            drawLine(pingSamples.map((sample, index) => calculateLossAt(index)), '#fbbf24', 100);
        }

        function showHistoryTooltip(event) {
            if (!pingSamples.length) return;
            const rect = canvas.getBoundingClientRect();
            const index = Math.max(0, Math.min(
                pingSamples.length - 1,
                Math.round(((event.clientX - rect.left) / rect.width) * (pingSamples.length - 1))
            ));
            const ping = pingSamples[index];
            const tooltip = document.getElementById('history-tooltip');
            const containerRect = canvas.parentElement.getBoundingClientRect();
            tooltip.innerHTML =
                '<b>vor ' + ((pingSamples.length - 1 - index) / 2).toFixed(1) + ' s</b><br>' +
                'Ping: ' + (ping.ms !== null ? ping.ms + ' ms' : 'Timeout') + '<br>' +
                'Packet Loss: ' + calculateLossAt(index).toFixed(1) + '%';
            tooltip.style.display = 'block';
            tooltip.style.left = Math.max(8, Math.min(
                containerRect.width - 155,
                event.clientX - containerRect.left + 8
            )) + 'px';
            tooltip.style.top = Math.max(30, event.clientY - containerRect.top - 20) + 'px';
            clearTimeout(tooltip.hideTimer);
            tooltip.hideTimer = setTimeout(() => tooltip.style.display = 'none', 5000);
        }
        canvas.addEventListener('click', showHistoryTooltip);

        function updateLiveMetrics() {
            const start = performance.now();
            totalPings++;
            
            fetch('/api/stats', { cache: 'no-store' })
                .then(res => {
                    const latency = Math.round(performance.now() - start);
                    if (!res.ok) throw new Error();
                    pingSamples.push({ms: latency, ok: true});
                    if (pingSamples.length > 120) pingSamples.shift();
                    document.getElementById('live-ping').innerText = latency + ' ms';
                    return res.json();
                })
                .then(data => {
                    const recentSamples = pingSamples.slice(-60);
                    const lossRate = (recentSamples.filter(sample => !sample.ok).length /
                        Math.max(1, recentSamples.length) * 100).toFixed(1);
                    document.getElementById('live-loss').innerText = lossRate + '%';

                    drawChart();
                })
                .catch(() => {
                    failedPings++;
                    pingSamples.push({ms: null, ok: false});
                    if (pingSamples.length > 120) pingSamples.shift();
                    document.getElementById('live-ping').innerText = 'Timeout';
                    const recentSamples = pingSamples.slice(-60);
                    const lossRate = (recentSamples.filter(sample => !sample.ok).length /
                        Math.max(1, recentSamples.length) * 100).toFixed(1);
                    document.getElementById('live-loss').innerText = lossRate + '%';
                    drawChart();
                });
        }

        let cpuHistory = Array(60).fill(0);
        let ramHistory = Array(60).fill(0);
        const canvasCpuRam = document.getElementById('cpu-ram-chart');
        const ctxCpuRam = canvasCpuRam.getContext('2d');

        function resizeCpuRamCanvas() {
            canvasCpuRam.width = canvasCpuRam.parentElement.clientWidth - 32;
            canvasCpuRam.height = 130;
        }
        window.addEventListener('resize', resizeCpuRamCanvas);
        resizeCpuRamCanvas();

        function drawCpuRamChart() {
            ctxCpuRam.clearRect(0, 0, canvasCpuRam.width, canvasCpuRam.height);

            let maxVal = 100;
            const stepX = canvasCpuRam.width / (cpuHistory.length - 1 || 1);

            function drawLine(data, color) {
                ctxCpuRam.beginPath();
                ctxCpuRam.strokeStyle = color;
                ctxCpuRam.lineWidth = 2;
                for (let i = 0; i < data.length; i++) {
                    const val = data[i] || 0;
                    const x = i * stepX;
                    const y = canvasCpuRam.height - 10 - (val / maxVal) * (canvasCpuRam.height - 20);
                    if (i === 0) ctxCpuRam.moveTo(x, y);
                    else ctxCpuRam.lineTo(x, y);
                }
                ctxCpuRam.stroke();
            }

            ctxCpuRam.strokeStyle = 'rgba(255,255,255,0.05)';
            ctxCpuRam.lineWidth = 1;
            for (let i = 0; i < 4; i++) {
                let y = (canvasCpuRam.height / 4) * i;
                ctxCpuRam.beginPath();
                ctxCpuRam.moveTo(0, y);
                ctxCpuRam.lineTo(canvasCpuRam.width, y);
                ctxCpuRam.stroke();
            }

            drawLine(cpuHistory, '#34d399');
            drawLine(ramHistory, '#f87171');
        }

        function showCpuRamTooltip(event) {
            const rect = canvasCpuRam.getBoundingClientRect();
            const index = Math.max(0, Math.min(
                cpuHistory.length - 1,
                Math.round(((event.clientX - rect.left) / rect.width) * (cpuHistory.length - 1))
            ));
            const secondsAgo = cpuHistory.length - 1 - index;
            const cpu = cpuHistory[index];
            const ram = ramHistory[index];
            const tooltip = document.getElementById('cpu-ram-tooltip');
            const containerRect = canvasCpuRam.parentElement.getBoundingClientRect();
            tooltip.innerHTML =
                '<b>vor ' + secondsAgo + ' s</b><br>' +
                'CPU: ' + (typeof cpu === 'number' ? cpu.toFixed(1) : '--') + '%<br>' +
                'RAM: ' + (typeof ram === 'number' ? ram.toFixed(1) : '--') + '%';
            tooltip.style.display = 'block';
            tooltip.style.left = Math.max(8, Math.min(
                containerRect.width - 155,
                event.clientX - containerRect.left + 8
            )) + 'px';
            tooltip.style.top = Math.max(30, event.clientY - containerRect.top - 20) + 'px';
            clearTimeout(tooltip.hideTimer);
            tooltip.hideTimer = setTimeout(() => tooltip.style.display = 'none', 5000);
        }
        canvasCpuRam.addEventListener('click', showCpuRamTooltip);

        function fetchLiveCpuRam() {
            fetch('/api/cpu-ram', { cache: 'no-store' })
                .then(res => res.json())
                .then(data => {
                    const cpu = typeof data.cpu === 'number' ? data.cpu : null;
                    const ram = typeof data.ram === 'number' ? data.ram : null;
                    const wifiDown = typeof data.wifi_down_mbps === 'number' ? data.wifi_down_mbps : null;
                    const wifiUp = typeof data.wifi_up_mbps === 'number' ? data.wifi_up_mbps : null;
                    
                    document.getElementById('live-cpu').innerText = cpu === null ? 'nicht verfügbar' : cpu.toFixed(1) + '%';
                    document.getElementById('live-ram').innerText = ram === null ? 'nicht verfügbar' : ram.toFixed(1) + '%';
                    const temperature = typeof data.phone_temperature_c === 'number'
                        ? data.phone_temperature_c : null;
                    document.getElementById('live-temperature').innerText =
                        temperature === null ? 'nicht verfügbar' : temperature.toFixed(1) + ' °C';
                    document.getElementById('live-temperature').title =
                        data.phone_temperature_source || '';
                    document.getElementById('live-cpu').title = data.source || '';
                    document.getElementById('live-ram').title = data.source || '';
                    document.getElementById('live-wifi-down').innerText = wifiDown === null ? 'nicht verfügbar' : wifiDown.toFixed(2) + ' Mbit/s';
                    document.getElementById('live-wifi-up').innerText = wifiUp === null ? 'nicht verfügbar' : wifiUp.toFixed(2) + ' Mbit/s';
                    document.getElementById('wifi-source').innerText =
                        'Quelle: ' + (data.wifi_interfaces || 'nicht erkannt');
                    document.getElementById('live-wifi-down').title = data.wifi_interfaces || '';
                    document.getElementById('live-wifi-up').title = data.wifi_interfaces || '';

                    cpuHistory.push(cpu === null ? (cpuHistory[cpuHistory.length - 1] || 0) : cpu);
                    ramHistory.push(ram === null ? (ramHistory[ramHistory.length - 1] || 0) : ram);
                    if (cpuHistory.length > 60) cpuHistory.shift();
                    if (ramHistory.length > 60) ramHistory.shift();

                    wifiDownHistory.push(wifiDown === null ? 0 : wifiDown);
                    wifiUpHistory.push(wifiUp === null ? 0 : wifiUp);
                    if (wifiDownHistory.length > 60) wifiDownHistory.shift();
                    if (wifiUpHistory.length > 60) wifiUpHistory.shift();

                    drawCpuRamChart();
                    drawWifiChart();
                })
                .catch(() => {
                    document.getElementById('live-cpu').innerText = 'nicht verfügbar';
                    document.getElementById('live-ram').innerText = 'nicht verfügbar';
                    document.getElementById('live-temperature').innerText = 'nicht verfügbar';
                    document.getElementById('live-wifi-down').innerText = 'nicht verfügbar';
                    document.getElementById('live-wifi-up').innerText = 'nicht verfügbar';
                    document.getElementById('wifi-source').innerText = 'WLAN-Messung nicht erreichbar';
                });
        }

        let wifiDownHistory = Array(60).fill(0);
        let wifiUpHistory = Array(60).fill(0);
        const canvasWifi = document.getElementById('wifi-chart');
        const ctxWifi = canvasWifi.getContext('2d');

        function resizeWifiCanvas() {
            canvasWifi.width = canvasWifi.parentElement.clientWidth - 32;
            canvasWifi.height = 130;
        }
        window.addEventListener('resize', resizeWifiCanvas);
        resizeWifiCanvas();

        function drawWifiChart() {
            ctxWifi.clearRect(0, 0, canvasWifi.width, canvasWifi.height);

            // Skala passt sich dynamisch an den größten aktuell sichtbaren
            // Wert an (mit kleiner Mindesthöhe), damit auch geringer
            // Datenverkehr noch sichtbar ausschlägt.
            const maxVal = Math.max(1, ...wifiDownHistory, ...wifiUpHistory) * 1.15;
            const stepX = canvasWifi.width / (wifiDownHistory.length - 1 || 1);

            function drawLine(data, color) {
                ctxWifi.beginPath();
                ctxWifi.strokeStyle = color;
                ctxWifi.lineWidth = 2;
                for (let i = 0; i < data.length; i++) {
                    const val = data[i] || 0;
                    const x = i * stepX;
                    const y = canvasWifi.height - 10 - (val / maxVal) * (canvasWifi.height - 20);
                    if (i === 0) ctxWifi.moveTo(x, y);
                    else ctxWifi.lineTo(x, y);
                }
                ctxWifi.stroke();
            }

            ctxWifi.strokeStyle = 'rgba(255,255,255,0.05)';
            ctxWifi.lineWidth = 1;
            for (let i = 0; i < 4; i++) {
                let y = (canvasWifi.height / 4) * i;
                ctxWifi.beginPath();
                ctxWifi.moveTo(0, y);
                ctxWifi.lineTo(canvasWifi.width, y);
                ctxWifi.stroke();
            }

            drawLine(wifiDownHistory, '#34d399');
            drawLine(wifiUpHistory, '#f87171');
        }

        function showWifiTooltip(event) {
            const rect = canvasWifi.getBoundingClientRect();
            const index = Math.max(0, Math.min(
                wifiDownHistory.length - 1,
                Math.round(((event.clientX - rect.left) / rect.width) * (wifiDownHistory.length - 1))
            ));
            const secondsAgo = wifiDownHistory.length - 1 - index;
            const down = wifiDownHistory[index];
            const up = wifiUpHistory[index];
            const tooltip = document.getElementById('wifi-tooltip');
            const containerRect = canvasWifi.parentElement.getBoundingClientRect();
            tooltip.innerHTML =
                '<b>vor ' + secondsAgo + ' s</b><br>' +
                'Down: ' + (typeof down === 'number' ? down.toFixed(2) : '--') + ' Mbit/s<br>' +
                'Up: ' + (typeof up === 'number' ? up.toFixed(2) : '--') + ' Mbit/s';
            tooltip.style.display = 'block';
            tooltip.style.left = Math.max(8, Math.min(
                containerRect.width - 155,
                event.clientX - containerRect.left + 8
            )) + 'px';
            tooltip.style.top = Math.max(30, event.clientY - containerRect.top - 20) + 'px';
            clearTimeout(tooltip.hideTimer);
            tooltip.hideTimer = setTimeout(() => tooltip.style.display = 'none', 5000);
        }
        canvasWifi.addEventListener('click', showWifiTooltip);

        setInterval(fetchLiveCpuRam, 1000);
        setInterval(updateLiveMetrics, 500);
        updateLiveMetrics();
        fetchLiveCpuRam();
    </script>
</body>
</html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

VPN_WARN_HTML = '''<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"><title>VPN Erkannt</title>
<style>
body { background: #030008; color: #fff; font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.card { background: rgba(20, 15, 35, 0.8); border: 1px solid rgba(239, 68, 68, 0.4); padding: 40px; border-radius: 20px; text-align: center; max-width: 400px; box-shadow: 0 0 30px rgba(239, 68, 68, 0.2); }
h2 { color: #f87171; margin-top: 0; }
</style></head>
<body>__BG_ANIMATION__<div class="card"><h2>🛡️ VPN / Proxy Erkannt</h2><p style="color: #8b92b2;">Der Zugriff über VPN-, Proxy- oder Hosting-Netzwerke ist nicht gestattet. Bitte deaktiviere dein VPN.</p></div></body></html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

OVERLOAD_HTML = '''<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Server ausgelastet</title>
<style>
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; justify-content:center; align-items:center; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color:#fff; overflow:hidden; position:relative; background:#05030c; }
.pulseBg{position:fixed;inset:0;z-index:-1;overflow:hidden;background:radial-gradient(circle at 50% 55%, #1c1030 0%, #05030c 70%);}
.pulseGlow{position:absolute; top:50%; left:50%; width:70vmax; height:70vmax; transform:translate(-50%,-50%); background:radial-gradient(circle, rgba(251,191,36,0.16), transparent 65%); animation:glowPulse 5s ease-in-out infinite;}
@keyframes glowPulse{0%,100%{opacity:0.45; transform:translate(-50%,-50%) scale(0.9);}50%{opacity:1; transform:translate(-50%,-50%) scale(1.12);}}
.pulseRing{position:absolute; top:50%; left:50%; border:2px solid rgba(251,191,36,0.4); border-radius:50%; transform:translate(-50%,-50%); width:10px; height:10px; animation:ringExpand 3.6s ease-out infinite;}
.pulseRing.r2{animation-delay:1.2s; border-color:rgba(217,119,6,0.32);}
.pulseRing.r3{animation-delay:2.4s; border-color:rgba(192,132,252,0.28);}
@keyframes ringExpand{0%{width:10px;height:10px;opacity:0.9;}100%{width:150vmax;height:150vmax;opacity:0;}}
.pulseParticle{position:absolute; bottom:-10px; width:3px; height:3px; border-radius:50%; background:rgba(251,191,36,0.75); box-shadow:0 0 6px rgba(251,191,36,0.8); animation:particleRise linear infinite;}
@keyframes particleRise{0%{transform:translateY(0) scale(1); opacity:0;}8%{opacity:1;}100%{transform:translateY(-110vh) scale(0.3); opacity:0;}}
@media (prefers-reduced-motion: reduce){.pulseRing,.pulseGlow,.pulseParticle{animation:none;}}
.card { background: rgba(20, 15, 35, 0.82); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(251, 191, 36, 0.4); padding: 40px; border-radius: 20px; text-align: center; max-width: 420px; box-shadow: 0 0 40px rgba(251,191,36,0.15); position:relative; z-index:1; }
h2 { color: #fbbf24; margin-top: 0; }
</style></head>
<body>
<div class="pulseBg">
  <div class="pulseGlow"></div>
  <div class="pulseRing r1"></div>
  <div class="pulseRing r2"></div>
  <div class="pulseRing r3"></div>
  <div class="pulseParticle" style="left:6%; animation-duration:7.5s; animation-delay:0s;"></div>
  <div class="pulseParticle" style="left:14%; animation-duration:9.2s; animation-delay:1.1s;"></div>
  <div class="pulseParticle" style="left:23%; animation-duration:6.8s; animation-delay:2.4s;"></div>
  <div class="pulseParticle" style="left:33%; animation-duration:8.4s; animation-delay:0.6s;"></div>
  <div class="pulseParticle" style="left:41%; animation-duration:7.1s; animation-delay:3.2s;"></div>
  <div class="pulseParticle" style="left:52%; animation-duration:9.6s; animation-delay:1.8s;"></div>
  <div class="pulseParticle" style="left:61%; animation-duration:6.5s; animation-delay:0.3s;"></div>
  <div class="pulseParticle" style="left:69%; animation-duration:8.9s; animation-delay:2.9s;"></div>
  <div class="pulseParticle" style="left:78%; animation-duration:7.7s; animation-delay:1.4s;"></div>
  <div class="pulseParticle" style="left:86%; animation-duration:9.0s; animation-delay:0.9s;"></div>
  <div class="pulseParticle" style="left:93%; animation-duration:6.9s; animation-delay:2.1s;"></div>
</div>
<div class="card">
  <div style="font:700 13px/1 ui-monospace, SFMono-Regular, Menlo, monospace; color:#fbbf24; letter-spacing:.08em; margin-bottom:16px;">HTTP ERROR</div>
  <div style="font:800 64px/1 ui-monospace, SFMono-Regular, Menlo, monospace; color:#fbbf24; text-shadow:0 0 18px rgba(251,191,36,.35);">503</div>
  <h2>Service Unavailable</h2>
  <p style="color:#8b92b2; line-height:1.6;">Der Server ist aktuell ausgelastet und kann diese Anfrage nicht bearbeiten.</p>
  <p style="color:#fbbf24; font-size:12px; margin-bottom:0;">Server-Limit erreicht · Bitte später manuell erneut versuchen.</p>
</div>
</body></html>'''

COOLDOWN_HTML = '''<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"><title>Rate Limit</title>
<style>
body { background: #030008; color: #fff; font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.card { background: rgba(20, 15, 35, 0.8); border: 1px solid rgba(251, 191, 36, 0.4); padding: 40px; border-radius: 20px; text-align: center; max-width: 400px; }
h2 { color: #fbbf24; margin-top: 0; }
</style></head>
<body>__BG_ANIMATION__<div class="card"><h2>⏳ Zu viele Anfragen</h2><p style="color: #8b92b2;">Du hast das Anfragelimit erreicht. Bitte warte <b style="color:#fff;" id="cd-timer">__REMAINING__</b> Sekunden.</p></div>
<script>
    let timeLeft = __REMAINING__;
    const timerElem = document.getElementById('cd-timer');
    const interval = setInterval(() => {
        timeLeft--;
        if (timerElem) timerElem.innerText = timeLeft;
        if (timeLeft <= 0) {
            clearInterval(interval);
            window.location.reload();
        }
    }, 1000);
</script>
</body></html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

BANNED_HTML = '''<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"><title>Zugriff Verweigert</title>
<style>
body { background: #030008; color: #fff; font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.card { background: rgba(20, 15, 35, 0.8); border: 1px solid rgba(239, 68, 68, 0.4); padding: 40px; border-radius: 20px; text-align: center; max-width: 400px; }
h2 { color: #f87171; margin-top: 0; }
</style></head>
<body>__BG_ANIMATION__<div class="card"><h2>🚫 Zugriff Verweigert</h2><p style="color: #8b92b2;">__REASON_TEXT__</p></div></body></html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

MAINTENANCE_HTML = '''<!DOCTYPE html>
<html lang="de"><head><meta charset="UTF-8"><title>Wartungsarbeiten</title>
<style>
body { background: #030008; color: #fff; font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.card { background: rgba(20, 15, 35, 0.8); border: 1px solid rgba(192, 132, 252, 0.4); padding: 40px; border-radius: 20px; text-align: center; max-width: 400px; }
h2 { color: #c084fc; margin-top: 0; }
</style></head>
<body>__BG_ANIMATION__<div class="card"><h2>🔧 Wartungsarbeiten</h2><p style="color: #8b92b2;">Der Server befindet sich zurzeit im Wartungsmodus. Bitte versuche es später noch einmal.</p></div></body></html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

ADMIN_LOGIN_HTML = '''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anmeldung</title>
    <style>
        body { margin: 0; background: #030008; color: white; font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; overflow: hidden; }
        .login-card { background: rgba(20, 15, 35, 0.8); backdrop-filter: blur(24px); border: 1px solid rgba(168, 85, 247, 0.4); padding: 40px 30px; border-radius: 28px; width: 100%; max-width: 340px; box-sizing: border-box; text-align: center; box-shadow: 0 30px 60px -12px rgba(0, 0, 0, 0.8), 0 0 40px rgba(168, 85, 247, 0.2); animation: popIn 0.5s ease-out; }
        @keyframes popIn { from { opacity: 0; transform: scale(0.9) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        h3 { margin: 0 0 6px 0; font-size: 20px; color: #fff; font-weight: 600; }
        p { color: #8b92b2; font-size: 12px; margin: 0 0 24px 0; }
        .input-group { text-align: left; margin-bottom: 16px; }
        label { display: block; font-size: 11px; color: #8b92b2; margin-bottom: 6px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        input { width: 100%; padding: 12px 14px; background: rgba(5, 3, 10, 0.7); border: 1px solid rgba(255, 255, 255, 0.12); color: #fff; border-radius: 12px; box-sizing: border-box; font-size: 14px; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
        input:focus { border-color: #c084fc; box-shadow: 0 0 10px rgba(192, 132, 252, 0.3); }
        button { width: 100%; padding: 12px; background: linear-gradient(135deg, #9333ea 0%, #6b21a8 100%); border: none; color: #fff; border-radius: 12px; font-weight: 600; cursor: pointer; font-size: 14px; box-shadow: 0 4px 15px rgba(147, 51, 234, 0.35); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        button:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(147, 51, 234, 0.5); }
    </style>
</head>
<body>
    __BG_ANIMATION__
    <div class="login-card">
        <h3>Login</h3>
        <p>Admin-Bereich</p>
        <form method="POST" action="/admin/login">
            <div class="input-group">
                <label>Passwort</label>
                <input type="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit">Anmelden</button>
        </form>
    </div>
</body>
</html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

ADMIN_PANEL_HTML = '''<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin-Steuerung</title>
    <style>
        :root {
            --bg: #030008;
            --card-bg: rgba(20, 15, 35, 0.8);
            --border: rgba(255, 255, 255, 0.08);
            --text: #f3f4f6;
            --text-muted: #8b92b2;
            --primary: #c084fc;
            --danger: #f87171;
            --success: #34d399;
            --warning: #fbbf24;
        }
        body { background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 16px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; box-sizing: border-box; }
        .container { width: 100%; max-width: 660px; margin-top: 10px; margin-bottom: 40px; }
        .card { background: var(--card-bg); backdrop-filter: blur(24px); border: 1px solid var(--border); padding: 28px; border-radius: 28px; box-shadow: 0 30px 60px -12px rgba(0, 0, 0, 0.8), 0 0 40px rgba(0,0,0,0.4); animation: floatIn 0.5s ease-out; }
        @keyframes floatIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        .header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 18px; font-weight: 600; }
        .sub-header { font-size: 12px; color: var(--text-muted); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .badge-aktiv { background: rgba(52, 211, 153, 0.12); border: 1px solid rgba(52, 211, 153, 0.35); color: var(--success); padding: 4px 12px; border-radius: 30px; font-size: 11px; font-weight: 600; box-shadow: 0 0 10px rgba(52, 211, 153, 0.15); }
        
        .nav-tabs { display: grid; grid-template-columns: repeat(6, 1fr); gap: 4px; background: rgba(5, 3, 10, 0.7); padding: 6px; border-radius: 14px; border: 1px solid var(--border); margin-bottom: 12px; }
        .tab-btn { padding: 10px 2px; text-align: center; font-size: 10px; font-weight: 600; color: var(--text-muted); background: transparent; border: none; border-radius: 10px; cursor: pointer; text-decoration: none; display: block; transition: all 0.2s ease; }
        .tab-btn.active { background: var(--primary); color: #05030a; box-shadow: 0 4px 15px rgba(192, 132, 252, 0.35); }
        
        .btn-sec-link { background: rgba(5, 3, 10, 0.7); color: var(--text); padding: 12px; text-align: center; border-radius: 14px; margin-bottom: 20px; display: block; text-decoration: none; font-weight: 600; font-size: 13px; border: 1px solid var(--border); transition: all 0.2s ease; }
        .btn-sec-link.active { background: var(--primary); color: #05030a; border-color: var(--primary); box-shadow: 0 4px 15px rgba(192, 132, 252, 0.35); }

        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.3s ease-out; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        
        table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: ui-monospace, monospace; }
        th, td { padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: left; }
        th { color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
        
        .btn { padding: 10px 14px; border-radius: 10px; font-weight: 600; cursor: pointer; border: none; font-size: 12px; color: #fff; text-decoration: none; display: inline-block; text-align: center; transition: all 0.2s ease; }
        .btn-primary { background: linear-gradient(135deg, #9333ea 0%, #6b21a8 100%); box-shadow: 0 4px 15px rgba(147, 51, 234, 0.35); color: #fff; }
        .btn-danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); box-shadow: 0 4px 15px rgba(239, 68, 68, 0.35); }
        .btn-warning { background: linear-gradient(135deg, #fbbf24 0%, #d97706 100%); color: #05030a; box-shadow: 0 4px 15px rgba(251, 191, 36, 0.35); }
        .btn-success { background: linear-gradient(135deg, #34d399 0%, #059669 100%); box-shadow: 0 4px 15px rgba(52, 211, 153, 0.35); color: #05030a; }
        .btn:hover { transform: translateY(-2px); }
        
        input[type="text"], input[type="number"], input[type="password"], textarea { width: 100%; background: rgba(5, 3, 10, 0.7); border: 1px solid var(--border); color: #fff; padding: 11px 14px; border-radius: 10px; box-sizing: border-box; margin-bottom: 10px; font-size: 13px; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
        input:focus { border-color: var(--primary); box-shadow: 0 0 10px rgba(192, 132, 252, 0.25); }
        
        .ip-row { display: flex; justify-content: space-between; align-items: center; background: rgba(5, 3, 10, 0.7); border: 1px solid var(--border); padding: 10px 14px; border-radius: 10px; margin-bottom: 8px; font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }
        .stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 20px; }
        .stat-card { background: rgba(5, 3, 10, 0.7); border: 1px solid var(--border); padding: 14px; border-radius: 14px; text-align: center; }
        .stat-card .val { font-size: 18px; font-weight: 700; color: var(--primary); margin-top: 6px; font-variant-numeric: tabular-nums; text-shadow: 0 0 10px rgba(192, 132, 252, 0.3); }
        .stat-card .lbl { font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
        .section-box { background: rgba(5, 3, 10, 0.45); padding: 16px; border-radius: 16px; border: 1px solid var(--border); margin-bottom: 16px; }
        .checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 14px; font-size: 12px; }
        .checkbox-label { display: flex; align-items: center; gap: 8px; background: rgba(20, 15, 35, 0.6); padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); cursor: pointer; transition: border-color 0.2s; }
        .checkbox-label:hover { border-color: rgba(192, 132, 252, 0.4); }
    </style>
</head>
<body>
    __BG_ANIMATION__
    <div class="container">
        <div class="card">
            <div class="header-row">
                <span>Admin-Steuerung</span>
                <span class="badge-aktiv">● Aktiv</span>
            </div>
            <div class="sub-header">
                <span>Authentifiziert</span>
                <a href="/" style="color:var(--primary); text-decoration:none; font-weight:600;">← Zur Startseite</a>
            </div>

            <div class="nav-tabs">
                <a href="/admin?tab=logs" class="tab-btn __TAB_LOGS_ACTIVE__">Logs</a>
                <a href="/admin?tab=geo" class="tab-btn __TAB_GEO_ACTIVE__">Geo-Top</a>
                <a href="/admin?tab=status" class="tab-btn __TAB_STATUS_ACTIVE__">Status</a>
                <a href="/admin?tab=timer" class="tab-btn __TAB_TIMER_ACTIVE__">⏱️ Timer</a>
                <a href="/admin?tab=account" class="tab-btn __TAB_ACCOUNT_ACTIVE__">Passwort</a>
                <a href="/admin?tab=scanner" class="tab-btn __TAB_SCANNER_ACTIVE__">Scanner</a>
            </div>

            <a href="/admin?tab=security" class="btn-sec-link __TAB_SEC_BTN_ACTIVE__">⚙️ Sicherheit, VPN-Filter & Sperren</a>

            <div class="tab-content __CONTENT_LOGS_ACTIVE__">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px; font-weight: 600;">Live-Anfragen im System:</div>
                <div style="max-height: 300px; overflow-y: auto;">
                    <table>
                        <tr><th>Zeit</th><th>IP</th><th>Pfad</th><th>Status</th></tr>
                        __LOGS_TABLE__
                    </table>
                </div>

                <div class="section-box" style="margin-top:16px;">
                    <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px; font-weight: 600;">📊 Anfragen-Diagramm (auf einen Balken klicken für Details):</div>
                    <div id="reqChartWrap" style="position:relative;">
                        <div id="reqChart" style="display:flex; align-items:flex-end; gap:3px; height:120px; padding:4px 2px; overflow-x:auto;"></div>
                    </div>
                    <div id="reqChartDetail" style="display:none; margin-top:10px; background: rgba(5, 3, 10, 0.7); border: 1px solid var(--border); border-radius: 10px; padding: 10px 14px; font-family: ui-monospace, monospace; font-size: 12px;"></div>
                    <div id="reqChartEmpty" style="display:none; font-size:12px; color:var(--text-muted); text-align:center; padding:10px;">Noch keine Anfragen aufgezeichnet.</div>
                </div>

                <script>
                (function(){
                    var data = __LOGS_CHART_JSON__;
                    var wrap = document.getElementById('reqChart');
                    var detail = document.getElementById('reqChartDetail');
                    var emptyMsg = document.getElementById('reqChartEmpty');
                    if (!Array.isArray(data) || data.length === 0) {
                        if (emptyMsg) emptyMsg.style.display = 'block';
                        return;
                    }
                    var statusColor = function(status){
                        var s = parseInt(status, 10);
                        if (s >= 500) return 'linear-gradient(180deg, #f87171, #ef4444)';
                        if (s >= 400) return 'linear-gradient(180deg, #fbbf24, #d97706)';
                        if (s >= 300) return 'linear-gradient(180deg, #38bdf8, #0ea5e9)';
                        return 'linear-gradient(180deg, #34d399, #10b981)';
                    };
                    data.forEach(function(entry, idx){
                        var bar = document.createElement('div');
                        bar.title = entry.time + ' – ' + entry.ip + ' – ' + entry.path;
                        bar.style.cssText = 'flex:0 0 10px; width:10px; height:' + (30 + (idx % 7) * 12) + 'px; align-self:flex-end; border-radius:4px 4px 0 0; cursor:pointer; background:' + statusColor(entry.status) + '; opacity:0.85; transition:opacity 0.15s, transform 0.15s;';
                        bar.addEventListener('mouseenter', function(){ bar.style.opacity = '1'; bar.style.transform = 'scaleY(1.05)'; });
                        bar.addEventListener('mouseleave', function(){ bar.style.opacity = '0.85'; bar.style.transform = 'none'; });
                        bar.addEventListener('click', function(){
                            detail.style.display = 'block';
                            detail.replaceChildren();
                            var title = document.createElement('b');
                            title.style.color = 'var(--primary)';
                            title.textContent = 'Anfrage-Details';
                            var lines = [
                                'Zeit: ' + entry.time,
                                'IP: ' + entry.ip,
                                'Pfad: ' + entry.path,
                                'Status: ' + entry.status
                            ];
                            detail.appendChild(title);
                            lines.forEach(function(line){
                                detail.appendChild(document.createElement('br'));
                                detail.appendChild(document.createTextNode(line));
                            });
                        });
                        wrap.appendChild(bar);
                    });
                    wrap.scrollLeft = wrap.scrollWidth;
                })();
                </script>
            </div>

            <div class="tab-content __CONTENT_GEO_ACTIVE__">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px; font-weight: 600;">Top Länder-Herkunft:</div>
                <div style="max-height: 300px; overflow-y: auto;">
                    <table>
                        <tr><th>Land</th><th>Aufrufe</th></tr>
                        __GEO_TABLE__
                    </table>
                </div>
            </div>

            <div class="tab-content __CONTENT_TIMER_ACTIVE__">
                <div class="section-box">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 12px; color: var(--primary);">⏱️ Einmaliger Timer-Neustart</div>
                    <form action="/admin/start-timer-restart" method="POST">
                        <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:6px; font-weight:600;">Neustart in Sekunden ausführen:</label>
                        <input type="number" name="timer_seconds" value="10" min="1" required style="margin-bottom:12px;">
                        <button type="submit" class="btn btn-warning" style="width:100%; font-weight:700;">⏱️ Timer-Neustart starten & Nutzer benachrichtigen</button>
                    </form>
                </div>

                <div class="section-box">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 12px; color: var(--primary);">🔄 Automatischer Intervall-Neustart</div>
                    <form action="/admin/update-settings" method="POST">
                        <input type="hidden" name="form_submitted" value="1">
                        <div style="margin-bottom: 12px;">
                            <button type="submit" name="toggle_schedrestart" value="1" class="btn __SCHEDRESTART_BTN_CLASS__" style="width:100%;">Intervall-Restart Status: __SCHEDRESTART_TEXT__</button>
                        </div>
                        <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:6px; font-weight:600;">Alle X Sekunden automatisch neustarten:</label>
                        <input type="number" name="scheduled_restart_interval" value="__SCHEDULED_RESTART_INTERVAL__" required style="margin-bottom:12px;">
                        <button type="submit" class="btn btn-primary" style="width:100%;">Intervall Speichern</button>
                    </form>
                </div>
            </div>

            <div class="tab-content __CONTENT_SECURITY_ACTIVE__">
                <form action="/admin/restart-manual" method="POST" style="margin-bottom: 16px;">
                    <button type="submit" class="btn btn-danger" style="width: 100%; padding: 12px; font-weight: 700;">🔄 Server Jetzt Sofort Neustarten</button>
                </form>

                <form action="/admin/update-settings" method="POST">
                    <input type="hidden" name="form_submitted" value="1">
                    <div class="section-box">
                        <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 10px; font-weight: 700; text-transform:uppercase; letter-spacing:0.05em;">GERÄTE, VPN & BOT ZULASSUNG</label>
                        <div class="checkbox-grid">
                            <label class="checkbox-label"><input type="checkbox" name="allow_desktop" __CHECKED_DESKTOP__> Desktop Rechner</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_mobile" __CHECKED_MOBILE__> Mobile (Handys)</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_chrome" __CHECKED_CHROME__> Google Chrome</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_firefox" __CHECKED_FIREFOX__> Mozilla Firefox</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_safari" __CHECKED_SAFARI__> Apple Safari</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_edge" __CHECKED_EDGE__> Microsoft Edge</label>
                            <label class="checkbox-label" style="grid-column: span 2;"><input type="checkbox" name="allow_bots" __CHECKED_BOTS__> Bots / Crawler zulassen</label>
                            <label class="checkbox-label" style="grid-column: span 2;"><input type="checkbox" name="block_vpn" __CHECKED_VPN__> VPN & Proxy Warnscreen anzeigen</label>
                        </div>
                    </div>

                    <div class="section-box">
                        <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 10px; font-weight: 700; text-transform:uppercase; letter-spacing:0.05em;">WEITERLEITUNGEN (BEI GEO-BLOCKS)</label>
                        
                        <div style="margin-bottom: 14px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px; font-weight: 600;">Manuelle Weiterleitungs-IPs</label>
                            <input type="text" name="ip_to_redirect" placeholder="z.B. 192.168.1.75" style="margin-bottom: 8px;">
                            <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 600;">Aktive Weiterleitungs-IPs:</div>
                            <div style="max-height: 90px; overflow-y: auto;" id="redirect-ips-container">
                                __REDIRECT_IPS_LIST__
                            </div>
                        </div>

                        <div class="checkbox-grid" style="grid-template-columns: 1fr; margin-bottom: 10px; margin-top: 12px;">
                            <label class="checkbox-label"><input type="checkbox" name="redirect_unknown" __CHECKED_REDIR_UNKN__> Unbekannte Herkunft weiterleiten</label>
                        </div>
                        
                        <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px; font-weight: 600;">Länder weiterleiten (Kommagetrennt)</label>
                        <input type="text" name="redirect_countries" value="__REDIRECT_COUNTRIES__" placeholder="z.B. China, Russia" style="margin-bottom: 12px;">

                        <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px; font-weight: 600;">Ziel-URL</label>
                        <input type="text" name="redirect_url" value="__REDIRECT_URL__" placeholder="z.B. https://www.google.com" style="margin-bottom: 0;">
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
                        <div class="section-box" style="margin-bottom:0;">
                            <div style="font-size: 12px; font-weight: 600; margin-bottom: 6px;">IP manuell sperren:</div>
                            <input type="text" name="ip_to_ban" placeholder="z.B. 192.168.1.50" style="margin-bottom: 8px;">
                            
                            <div style="font-size: 12px; font-weight: 600; margin: 12px 0 6px 0;">Permanente Bans:</div>
                            <div style="max-height: 90px; overflow-y: auto;" id="banned-list-container">
                                __BANNED_LIST__
                            </div>
                            
                            <div style="font-size: 12px; font-weight: 600; margin: 12px 0 6px 0;">Aktive Cooldowns:</div>
                            <div style="max-height: 90px; overflow-y: auto;" id="temp-banned-container">
                                __TEMP_BANNED_LIST__
                            </div>
                        </div>

                        <div class="section-box" style="margin-bottom:0;">
                            <div style="font-size: 12px; font-weight: 600; margin-bottom: 6px;">IP Whitelist:</div>
                            <input type="text" name="ip_to_wl" placeholder="z.B. 192.168.1.100" style="margin-bottom: 8px;">
                            
                            <div style="font-size: 12px; font-weight: 600; margin: 12px 0 6px 0;">Whitelisted:</div>
                            <div style="max-height: 110px; overflow-y: auto;" id="whitelist-container">
                                __WHITELIST_LIST__
                            </div>
                        </div>
                    </div>

                    <div class="section-box">
                        <div style="margin-bottom: 16px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 8px; font-weight: 700; text-transform:uppercase; letter-spacing:0.05em;">SYSTEM-STEUERUNG</label>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                                <button type="submit" name="toggle_maint" value="1" class="btn __MAINT_BTN_CLASS__" style="width:100%;">Wartung: __MAINT_TEXT__</button>
                                <button type="submit" name="toggle_autoban" value="1" class="btn __AUTOBAN_BTN_CLASS__" style="width:100%;">Auto-Cooldown: __AUTOBAN_TEXT__</button>
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr; gap: 10px; margin-bottom: 10px;">
                                <button type="submit" name="toggle_autorestart" value="1" class="btn __RESTART_BTN_CLASS__" style="width:100%;">Auto-Restart (DDoS): __RESTART_TEXT__</button>
                            </div>
                        </div>

                        <div style="margin-bottom: 16px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 8px; font-weight: 700; text-transform:uppercase; letter-spacing:0.05em;">SCHWELLENWERTE & DAUER</label>
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px;">Max. Anfragen / IP pro Sek.</label>
                            <input type="number" name="max_ip_req" value="__MAX_IP_REQ__" required style="margin-bottom:8px;">
                            
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px;">Cooldown-Dauer (Sek.)</label>
                            <input type="number" name="ban_duration" value="__BAN_DURATION__" required style="margin-bottom:8px;">
                            
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px;">Verzögerung (Sek.)</label>
                            <input type="number" step="0.1" name="throttle_delay" value="__THROTTLE_DELAY__" required style="margin-bottom:8px;">
                            
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 4px;">Restart RPS Schwelle</label>
                            <input type="number" name="restart_rps_threshold" value="__RESTART_RPS_THRESHOLD__" required style="margin-bottom:8px;">
                        </div>

                        <div style="margin-bottom: 16px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 8px; font-weight: 700; text-transform:uppercase; letter-spacing:0.05em;">GLOBALES SERVER-LIMIT (0 = AUS)</label>
                            <input type="number" name="server_limit" value="__SERVER_LIMIT__" placeholder="Max. RPS Schwelle" required style="margin-bottom:0;">
                        </div>

                        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px;">Einstellungen speichern</button>
                    </div>
                </form>
            </div>

            <div class="tab-content __CONTENT_STATUS_ACTIVE__">
                <div class="stats-row">
                    <div class="stat-card"><div class="lbl">200 OK</div><div class="val" style="color:var(--success);" id="stat-200">__STAT_200__</div></div>
                    <div class="stat-card"><div class="lbl">403</div><div class="val" style="color:var(--danger);" id="stat-403">__STAT_403__</div></div>
                    <div class="stat-card"><div class="lbl">503 / 429</div><div class="val" style="color:var(--warning);" id="stat-503">__STAT_503__</div></div>
                </div>
                <div style="font-size: 13px; margin-bottom: 12px; font-weight: 600;">Server-Status:</div>
                <div class="ip-row"><span>Aktuelle RPS</span><span style="color:var(--primary);" id="curr-rps-val">__CURRENT_RPS__</span></div>
                <div class="ip-row"><span>Blocked RPS</span><span style="color:var(--danger);" id="curr-blocked-val">__CURRENT_BLOCKED_RPS__</span></div>
                <div class="ip-row"><span>Überlastet RPS</span><span style="color:var(--warning);" id="curr-overload-val">__CURRENT_OVERLOAD_RPS__</span></div>
                <div class="ip-row"><span>Peak RPS</span><span style="color:var(--text); font-weight:bold;">__PEAK_RPS__</span></div>
                <div class="ip-row"><span>Aktive IP-Tracker</span><span style="color:var(--text); font-weight:bold;">__ACTIVE_IPS__</span></div>
            </div>

            <div class="tab-content __CONTENT_ACCOUNT_ACTIVE__">
                <div class="section-box">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 12px; color: var(--primary);">Passwort ändern</div>
                    <form action="/admin/update-password" method="POST">
                        <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px; font-weight:600;">Altes Passwort</label>
                        <input type="password" name="old_password" required placeholder="••••••••••••">
                        <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px; font-weight:600;">Neues Passwort</label>
                        <input type="password" name="new_password" required placeholder="••••••••••••">
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:6px;">Passwort Aktualisieren</button>
                    </form>
                </div>
            </div>

            <div class="tab-content __CONTENT_SCANNER_ACTIVE__">
                <div class="section-box">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 12px; color: var(--primary);">System & Server Details</div>
                    <div class="ip-row"><span>Python-Version</span><span>__PYTHON_VERSION__</span></div>
                    <div class="ip-row"><span>Startzeit</span><span>__START_TIME__</span></div>
                    <div class="ip-row"><span>Aktuelle Zeit</span><span>__CURRENT_SECOND__</span></div>
                    <div class="ip-row"><span>Uptime</span><span>__UPTIME__ Sekunden</span></div>
                </div>

                <div class="section-box">
                    <div style="font-size: 13px; font-weight: 700; margin-bottom: 12px; color: var(--primary);">Top User-Agents</div>
                    __TOP_UA_LIST__
                </div>
            </div>
        </div>
    </div>
</body>
</html>'''

def _record_application_traffic(received=0, sent=0):
    global APPLICATION_RX_BYTES, APPLICATION_TX_BYTES
    with STATE_LOCK:
        APPLICATION_RX_BYTES += max(0, int(received))
        APPLICATION_TX_BYTES += max(0, int(sent))


class _CountingReader:
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def read(self, *args, **kwargs):
        data = self._wrapped.read(*args, **kwargs)
        _record_application_traffic(received=len(data or b""))
        return data

    def readline(self, *args, **kwargs):
        data = self._wrapped.readline(*args, **kwargs)
        _record_application_traffic(received=len(data or b""))
        return data

    def readinto(self, buffer, *args, **kwargs):
        count = self._wrapped.readinto(buffer, *args, **kwargs)
        _record_application_traffic(received=count or 0)
        return count

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


class _CountingWriter:
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def write(self, data, *args, **kwargs):
        _record_application_traffic(sent=len(data or b""))
        return self._wrapped.write(data, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


class SecurityHandler(http.server.SimpleHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.rfile = _CountingReader(self.rfile)
        self.wfile = _CountingWriter(self.wfile)

    def handle(self):
        try:
            super().handle()
        except (ConnectionError, TimeoutError):
            # Clients sometimes leave while a response is still being sent.
            # That is normal for browsers and media players; stop this request
            # quietly instead of letting the server print a traceback.
            self.close_connection = True

    def log_message(self, format, *args):
        return

    def send_light_error(self, code, retry_after=None):
        body = LIGHT_ERROR_BODIES.get(
            code,
            b"<!doctype html><meta charset=utf-8><title>HTTP Error</title>"
            b"<body style='margin:2rem;background:#080610;color:#eee;font:16px system-ui'>"
            b"<h1>HTTP Error</h1></body>",
        )
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if retry_after is not None:
            self.send_header("Retry-After", str(max(1, int(retry_after))))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler baut standardmäßig pro Fehler eine große
        # dynamische HTML-Seite. Nutze stattdessen die vorgefertigten Bytes.
        self.send_light_error(code)

    def get_client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def serve_media_asset(self, path):
        media_name = urllib.parse.unquote(path[len("/media/"):])
        if (
            not media_name
            or media_name in {".", ".."}
            or "/" in media_name
            or "\\" in media_name
        ):
            self.send_error(404)
            return

        extension = os.path.splitext(media_name)[1].lower()
        if extension not in MEDIA_TYPE_BY_EXTENSION:
            self.send_error(404)
            return

        media_root = os.path.realpath(MEDIA_DIR)
        file_path = os.path.realpath(os.path.join(media_root, media_name))
        media_data = None
        try:
            if os.path.commonpath((media_root, file_path)) != media_root:
                self.send_error(404)
                return
            if not os.path.isfile(file_path):
                raise FileNotFoundError(file_path)
            file_size = os.path.getsize(file_path)
        except (OSError, ValueError):
            encoded_data = EMBEDDED_MEDIA_BASE64.get(media_name)
            if encoded_data is None:
                self.send_error(404)
                return
            try:
                media_data = base64.b64decode(encoded_data, validate=True)
            except (ValueError, TypeError):
                self.send_error(500, "Eingebettete Mediendatei ist beschädigt")
                return
            file_size = len(media_data)

        start = 0
        end = file_size - 1
        status_code = 200
        range_header = self.headers.get("Range", "")
        if range_header:
            match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header.strip())
            if not match:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{file_size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            range_start, range_end = match.groups()
            if not range_start:
                suffix_length = int(range_end or "0")
                if suffix_length <= 0 or file_size <= 0:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                start = max(0, file_size - suffix_length)
            else:
                start = int(range_start)
                end = min(int(range_end), file_size - 1) if range_end else file_size - 1

            if start >= file_size or start > end:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{file_size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status_code = 206

        content_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
        content_length = max(0, end - start + 1)
        media_kind = MEDIA_TYPE_BY_EXTENSION.get(extension, "file")
        disposition = "attachment" if media_kind == "file" else "inline"
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("Content-Disposition", f'{disposition}; filename="{media_name}"')
        if status_code == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
        self.end_headers()

        try:
            remaining = content_length
            if media_data is not None:
                offset = start
                while remaining > 0:
                    chunk = media_data[offset:offset + min(64 * 1024, remaining)]
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    offset += len(chunk)
                    remaining -= len(chunk)
            else:
                with open(file_path, "rb") as media_file:
                    media_file.seek(start)
                    while remaining > 0:
                        chunk = media_file.read(min(64 * 1024, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def do_GET(self):
        global TOTAL_REQUESTS_COUNT, PEAK_RPS
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)
        client_ip = self.get_client_ip()
        now = time.time()

        with STATE_LOCK:
            TOTAL_REQUESTS_COUNT += 1
            persist_total_requests = TOTAL_REQUESTS_COUNT % 250 == 0
        # Persist far less often than every 20th request and outside the state
        # lock. This reduces storage writes and keeps other requests moving.
        if persist_total_requests:
            save_settings()

        if path == "/api/stats":
            # Dieser interne Endpunkt wird vor den normalen Routenprüfungen
            # behandelt, zählt aber trotzdem als erlaubte Anfrage.
            update_traffic_history("success")
            with STATE_LOCK:
                while REQUEST_TIMESTAMPS and now - REQUEST_TIMESTAMPS[0] > WINDOW_SIZE:
                    REQUEST_TIMESTAMPS.popleft()
                REQUEST_TIMESTAMPS.append(now)
                current_rps = len(REQUEST_TIMESTAMPS)
                if current_rps > PEAK_RPS:
                    PEAK_RPS = current_rps

                data = {
                    "total": TOTAL_REQUESTS_COUNT,
                    "rps": current_rps,
                    "blocked_rps": CURRENT_SEC_BLOCKED,
                    "history": list(TRAFFIC_HISTORY)
                }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if path == "/api/cpu-ram":
            # Auch der Telemetrie-Endpunkt verlässt die Funktion vor dem
            # allgemeinen success-Aufruf weiter unten.
            update_traffic_history("success")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            with STATE_LOCK:
                remote_age = (
                    round(max(0.0, time.time() - REMOTE_PHONE_METRICS_LAST_AT), 1)
                    if REMOTE_PHONE_METRICS_LAST_AT > 0
                    else None
                )
                metrics = {
                    "cpu": GLOBAL_CPU,
                    "ram": GLOBAL_RAM,
                    "phone_temperature_c": PHONE_TEMPERATURE_C,
                    "phone_temperature_source": PHONE_TEMPERATURE_SOURCE,
                    "wifi_down_mbps": GLOBAL_WIFI_DOWN_MBPS,
                    "wifi_up_mbps": GLOBAL_WIFI_UP_MBPS,
                    "wan_capacity_mbps": WAN_CAPACITY_MBPS,
                    "wan_upload_capacity_mbps": WAN_UPLOAD_CAPACITY_MBPS,
                    "wan_utilization_percent": (
                        round((GLOBAL_WIFI_DOWN_MBPS / WAN_CAPACITY_MBPS) * 100.0, 1)
                        if GLOBAL_WIFI_DOWN_MBPS is not None
                        else None
                    ),
                    "live_line_down_mbps": (
                        round(max(0.0, GLOBAL_WIFI_DOWN_MBPS), 2)
                        if GLOBAL_WIFI_DOWN_MBPS is not None
                        else 0.0
                    ),
                    "live_line_up_mbps": (
                        round(max(0.0, GLOBAL_WIFI_UP_MBPS), 2)
                        if GLOBAL_WIFI_UP_MBPS is not None
                        else 0.0
                    ),
                    "wifi_interfaces": WIFI_INTERFACES_SOURCE,
                    "source": PHONE_METRICS_SOURCE,
                    "error": PHONE_METRICS_ERROR,
                    "remote_metrics_age_seconds": remote_age,
                    "remote_metrics_stale": remote_age is not None and remote_age > 5.0,
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            self.wfile.write(json.dumps(metrics).encode("utf-8"))
            return

        with STATE_LOCK:
            if client_ip in BANNED_IPS:
                update_traffic_history("blocked")
                status_code_stats[403] += 1
                self.send_light_error(403)
                return

            if client_ip in TEMPORARY_BANS:
                if now < TEMPORARY_BANS[client_ip]:
                    update_traffic_history("blocked")
                    status_code_stats[429] += 1
                    remaining = int(TEMPORARY_BANS[client_ip] - now)
                    self.send_light_error(429, retry_after=max(1, remaining))
                    return
                else:
                    del TEMPORARY_BANS[client_ip]

            # Serverweites Limit: zählt angenommene UND blockierte Anfragen der
            # aktuellen Sekunde zusammen. Wird die Summe erreicht, zeigt der
            # Server den Überlast-Screen an - egal ob diese konkrete Anfrage
            # sonst angenommen oder pro IP geblockt worden wäre. Beispiel:
            # 5 angenommene + 45 blockierte Anfragen bei Limit 50 lösen den
            # Screen aus.
            if SERVER_LIMIT > 0 and (CURRENT_SEC_SUCCESS + CURRENT_SEC_BLOCKED) >= SERVER_LIMIT:
                update_traffic_history("overload")
                status_code_stats[503] += 1
                remaining_wait = max(1, int(round(THROTTLE_DELAY)))
                self.send_light_error(503, retry_after=remaining_wait)
                return

            if client_ip not in WHITELISTED_IPS:
                timestamps = ip_request_counts[client_ip]
                while timestamps and now - timestamps[0] > 1.0:
                    timestamps.pop(0)
                timestamps.append(now)
                if len(timestamps) > MAX_REQUESTS_PER_IP:
                    if AUTO_BAN_ENABLED:
                        TEMPORARY_BANS[client_ip] = now + BAN_DURATION
                    update_traffic_history("blocked")
                    status_code_stats[429] += 1
                    self.send_light_error(429, retry_after=BAN_DURATION)
                    return

            if BLOCK_VPN and is_ip_vpn_or_proxy(client_ip):
                update_traffic_history("blocked")
                status_code_stats[403] += 1
                self.send_light_error(403)
                return

            if MAINTENANCE_MODE and not path.startswith("/admin"):
                update_traffic_history("blocked")
                status_code_stats[503] += 1
                self.send_light_error(503)
                return

        # Jede Anfrage, die die Schutzregeln passiert, wird als erlaubt
        # aufgezeichnet. Geblockte und überlastete Anfragen wurden oben an
        # ihrer jeweiligen Rückgabestelle bereits erfasst.
        update_traffic_history("success")
        ua = (self.headers.get("User-Agent", "Unbekannt") or "Unbekannt")[:512]
        with STATE_LOCK:
            if ua in user_agent_stats or len(user_agent_stats) < MAX_TRACKED_USER_AGENTS:
                user_agent_stats[ua] += 1
            stored_path = path[:256]
            ACTIVE_IP_TRACKER[client_ip] = {"last_seen": now, "path": stored_path}
            RECENT_LOGS.appendleft((time.strftime("%H:%M:%S"), client_ip, stored_path, 200))

        if path == "/api/media":
            media_items = []
            seen_names = set()
            try:
                with os.scandir(MEDIA_DIR) as entries:
                    for entry in entries:
                        extension = os.path.splitext(entry.name)[1].lower()
                        media_type = MEDIA_TYPE_BY_EXTENSION.get(extension)
                        if media_type and entry.is_file(follow_symlinks=False):
                            media_items.append({
                                "name": entry.name,
                                "type": media_type,
                            })
                            seen_names.add(entry.name)
            except FileNotFoundError:
                pass
            except OSError:
                if not EMBEDDED_MEDIA_BASE64:
                    self.send_error(500, "Medienordner kann nicht gelesen werden")
                    return

            for media_name in EMBEDDED_MEDIA_BASE64:
                extension = os.path.splitext(media_name)[1].lower()
                media_type = MEDIA_TYPE_BY_EXTENSION.get(extension)
                if (
                    media_type
                    and os.path.basename(media_name) == media_name
                    and media_name not in seen_names
                ):
                    media_items.append({"name": media_name, "type": media_type})

            media_items.sort(key=lambda item: item["name"].casefold())
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(media_items).encode("utf-8"))
            return

        if path.startswith("/media/"):
            self.serve_media_asset(path)
            return

        if path == "/":
            status_code_stats[200] += 1
            html_content = PUBLIC_HTML.replace("__TOTAL_REQ__", str(TOTAL_REQUESTS_COUNT))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))
            return

        if path == "/live-stats":
            status_code_stats[200] += 1
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(LIVE_STATS_HTML.encode("utf-8"))
            return

        if path == "/admin/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(ADMIN_LOGIN_HTML.encode("utf-8"))
            return

        if path == "/admin":
            cookie = SimpleCookie(self.headers.get("Cookie"))
            is_auth = False
            if "admin_session" in cookie:
                val = cookie["admin_session"].value
                with STATE_LOCK:
                    if val in ADMIN_SESSION:
                        is_auth = True

            if not is_auth:
                self.send_response(302)
                self.send_header("Location", "/admin/login")
                self.end_headers()
                return

            tab = query_params.get("tab", ["logs"])[0]
            
            logs_html = ""
            logs_chart_data = []
            with STATE_LOCK:
                for log in RECENT_LOGS:
                    logs_html += f"<tr><td>{log[0]}</td><td>{log[1]}</td><td>{log[2]}</td><td><span style='color:var(--success);'>{log[3]}</span></td></tr>"
                    logs_chart_data.append({
                        "time": log[0],
                        "ip": log[1],
                        "path": log[2],
                        "status": log[3],
                    })
            # Chronologisch aufsteigend fuers Diagramm (aeltester Balken zuerst).
            logs_chart_data.reverse()
            logs_json = json.dumps(logs_chart_data, ensure_ascii=False).replace("</", "<\\/")

            geo_html = ""
            with STATE_LOCK:
                for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                    geo_html += f"<tr><td>{country.upper()}</td><td>{count}</td></tr>"

            banned_list_html = ""
            with STATE_LOCK:
                for b_ip in BANNED_IPS:
                    banned_list_html += f'<div class="ip-row"><span>{b_ip}</span><a href="/admin/unban?ip={b_ip}" class="btn btn-danger" style="padding:4px 8px; font-size:10px;">Entsperren</a></div>'

            temp_banned_html = ""
            with STATE_LOCK:
                for t_ip in list(TEMPORARY_BANS.keys()):
                    rem = int(max(0, TEMPORARY_BANS[t_ip] - now))
                    temp_banned_html += f'<div class="ip-row"><span>{t_ip} ({rem}s)</span><a href="/admin/unban?ip={t_ip}" class="btn btn-warning" style="padding:4px 8px; font-size:10px;">Aufheben</a></div>'

            whitelist_html = ""
            with STATE_LOCK:
                for w_ip in WHITELISTED_IPS:
                    whitelist_html += f'<div class="ip-row"><span>{w_ip}</span><a href="/admin/unwl?ip={w_ip}" class="btn btn-danger" style="padding:4px 8px; font-size:10px;">Entfernen</a></div>'

            redirect_ips_html = ""
            with STATE_LOCK:
                for r_ip in REDIRECT_IPS:
                    redirect_ips_html += f'<div class="ip-row"><span>{r_ip}</span><a href="/admin/unredirect?ip={r_ip}" class="btn btn-danger" style="padding:4px 8px; font-size:10px;">Entfernen</a></div>'

            top_ua_html = ""
            with STATE_LOCK:
                for ua_str, count in sorted(user_agent_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                    top_ua_html += f'<div class="ip-row"><span style="word-break:break-all; font-size:10px;">{html.escape(ua_str)}</span><span style="font-weight:bold;">{count}</span></div>'

            panel = ADMIN_PANEL_HTML
            panel = panel.replace("__TAB_LOGS_ACTIVE__", "active" if tab == "logs" else "")
            panel = panel.replace("__TAB_GEO_ACTIVE__", "active" if tab == "geo" else "")
            panel = panel.replace("__TAB_STATUS_ACTIVE__", "active" if tab == "status" else "")
            panel = panel.replace("__TAB_TIMER_ACTIVE__", "active" if tab == "timer" else "")
            panel = panel.replace("__TAB_ACCOUNT_ACTIVE__", "active" if tab == "account" else "")
            panel = panel.replace("__TAB_SCANNER_ACTIVE__", "active" if tab == "scanner" else "")
            panel = panel.replace("__TAB_SEC_BTN_ACTIVE__", "active" if tab == "security" else "")

            panel = panel.replace("__CONTENT_LOGS_ACTIVE__", "active" if tab == "logs" else "")
            panel = panel.replace("__CONTENT_GEO_ACTIVE__", "active" if tab == "geo" else "")
            panel = panel.replace("__CONTENT_STATUS_ACTIVE__", "active" if tab == "status" else "")
            panel = panel.replace("__CONTENT_TIMER_ACTIVE__", "active" if tab == "timer" else "")
            panel = panel.replace("__CONTENT_ACCOUNT_ACTIVE__", "active" if tab == "account" else "")
            panel = panel.replace("__CONTENT_SCANNER_ACTIVE__", "active" if tab == "scanner" else "")
            panel = panel.replace("__CONTENT_SECURITY_ACTIVE__", "active" if tab == "security" else "")

            panel = panel.replace("__LOGS_TABLE__", logs_html)
            panel = panel.replace("__LOGS_CHART_JSON__", logs_json)
            panel = panel.replace("__GEO_TABLE__", geo_html)
            panel = panel.replace("__BANNED_LIST__", banned_list_html)
            panel = panel.replace("__TEMP_BANNED_LIST__", temp_banned_html)
            panel = panel.replace("__WHITELIST_LIST__", whitelist_html)
            panel = panel.replace("__REDIRECT_IPS_LIST__", redirect_ips_html)

            panel = panel.replace("__CHECKED_DESKTOP__", "checked" if ALLOW_DESKTOP else "")
            panel = panel.replace("__CHECKED_MOBILE__", "checked" if ALLOW_MOBILE else "")
            panel = panel.replace("__CHECKED_CHROME__", "checked" if ALLOW_CHROME else "")
            panel = panel.replace("__CHECKED_FIREFOX__", "checked" if ALLOW_FIREFOX else "")
            panel = panel.replace("__CHECKED_SAFARI__", "checked" if ALLOW_SAFARI else "")
            panel = panel.replace("__CHECKED_EDGE__", "checked" if ALLOW_EDGE else "")
            panel = panel.replace("__CHECKED_BOTS__", "checked" if ALLOW_BOTS else "")
            panel = panel.replace("__CHECKED_VPN__", "checked" if BLOCK_VPN else "")
            panel = panel.replace("__CHECKED_REDIR_UNKN__", "checked" if REDIRECT_UNKNOWN else "")

            panel = panel.replace("__REDIRECT_COUNTRIES__", ", ".join(REDIRECT_COUNTRIES))
            panel = panel.replace("__REDIRECT_URL__", REDIRECT_URL)

            panel = panel.replace("__MAINT_BTN_CLASS__", "btn-success" if MAINTENANCE_MODE else "btn-danger")
            panel = panel.replace("__MAINT_TEXT__", "Aktiv" if MAINTENANCE_MODE else "Inaktiv")
            panel = panel.replace("__AUTOBAN_BTN_CLASS__", "btn-success" if AUTO_BAN_ENABLED else "btn-danger")
            panel = panel.replace("__AUTOBAN_TEXT__", "Aktiv" if AUTO_BAN_ENABLED else "Inaktiv")
            panel = panel.replace("__RESTART_BTN_CLASS__", "btn-success" if AUTO_RESTART_ENABLED else "btn-danger")
            panel = panel.replace("__RESTART_TEXT__", "Aktiv" if AUTO_RESTART_ENABLED else "Inaktiv")

            panel = panel.replace("__SCHEDRESTART_BTN_CLASS__", "btn-success" if SCHEDULED_RESTART_ENABLED else "btn-danger")
            panel = panel.replace("__SCHEDRESTART_TEXT__", "Aktiv" if SCHEDULED_RESTART_ENABLED else "Inaktiv")
            panel = panel.replace("__SCHEDULED_RESTART_INTERVAL__", str(SCHEDULED_RESTART_INTERVAL))

            panel = panel.replace("__MAX_IP_REQ__", str(MAX_REQUESTS_PER_IP))
            panel = panel.replace("__BAN_DURATION__", str(BAN_DURATION))
            panel = panel.replace("__THROTTLE_DELAY__", str(THROTTLE_DELAY))
            panel = panel.replace("__RESTART_RPS_THRESHOLD__", str(RESTART_RPS_THRESHOLD))
            panel = panel.replace("__SERVER_LIMIT__", str(SERVER_LIMIT))

            with STATE_LOCK:
                curr_rps = len(REQUEST_TIMESTAMPS)
            panel = panel.replace("__STAT_200__", str(status_code_stats[200]))
            panel = panel.replace("__STAT_403__", str(status_code_stats[403]))
            panel = panel.replace("__STAT_503__", str(status_code_stats[503] + status_code_stats[429]))
            panel = panel.replace("__CURRENT_RPS__", str(curr_rps))
            panel = panel.replace("__CURRENT_BLOCKED_RPS__", str(CURRENT_SEC_BLOCKED))
            panel = panel.replace("__CURRENT_OVERLOAD_RPS__", str(CURRENT_SEC_OVERLOAD))
            panel = panel.replace("__PEAK_RPS__", str(PEAK_RPS))
            panel = panel.replace("__ACTIVE_IPS__", str(len(ACTIVE_IP_TRACKER)))

            panel = panel.replace("__PYTHON_VERSION__", sys.version.split()[0])
            panel = panel.replace("__START_TIME__", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(START_TIME)))
            panel = panel.replace("__CURRENT_SECOND__", time.strftime("%Y-%m-%d %H:%M:%S"))
            panel = panel.replace("__UPTIME__", str(int(time.time() - START_TIME)))
            panel = panel.replace("__TOP_UA_LIST__", top_ua_html)

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(panel.encode("utf-8"))
            return

        if path == "/admin/unban":
            ip_to_unban = query_params.get("ip", [""])[0]
            with STATE_LOCK:
                if ip_to_unban in BANNED_IPS:
                    BANNED_IPS.remove(ip_to_unban)
                if ip_to_unban in TEMPORARY_BANS:
                    del TEMPORARY_BANS[ip_to_unban]
            save_settings()
            self.send_response(302)
            self.send_header("Location", "/admin?tab=security")
            self.end_headers()
            return

        if path == "/admin/unwl":
            ip_to_unwl = query_params.get("ip", [""])[0]
            with STATE_LOCK:
                if ip_to_unwl in WHITELISTED_IPS:
                    WHITELISTED_IPS.remove(ip_to_unwl)
            save_settings()
            self.send_response(302)
            self.send_header("Location", "/admin?tab=security")
            self.end_headers()
            return

        if path == "/admin/unredirect":
            ip_to_unred = query_params.get("ip", [""])[0]
            with STATE_LOCK:
                if ip_to_unred in REDIRECT_IPS:
                    REDIRECT_IPS.remove(ip_to_unred)
            save_settings()
            self.send_response(302)
            self.send_header("Location", "/admin?tab=security")
            self.end_headers()
            return

        status_code_stats[404] += 1
        self.send_light_error(404)

    def do_POST(self):
        global ADMIN_PASSWORD_HASH
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        parsed_data = urllib.parse.parse_qs(body)
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/phone-metrics":
            global GLOBAL_CPU, GLOBAL_RAM, PHONE_METRICS_SOURCE, PHONE_METRICS_ERROR, REMOTE_PHONE_METRICS_UNTIL
            global GLOBAL_WIFI_DOWN_MBPS, GLOBAL_WIFI_UP_MBPS, WIFI_INTERFACES_SOURCE
            global REMOTE_PHONE_METRICS_LAST_AT
            global PHONE_TEMPERATURE_C, PHONE_TEMPERATURE_SOURCE
            supplied_token = self.headers.get("X-Phone-Metrics-Token", "")
            if PHONE_METRICS_TOKEN and supplied_token != PHONE_METRICS_TOKEN:
                self.send_response(401)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "Ungültiger Telefon-Metrik-Token"}).encode("utf-8"))
                return

            try:
                phone_data = json.loads(body)
                cpu_value = float(phone_data["cpu"])
                ram_value = float(phone_data["ram"])
                cpu_value = round(max(0.0, min(100.0, cpu_value)), 1)
                ram_value = round(max(0.0, min(100.0, ram_value)), 1)
                wifi_down_mbps = phone_data.get("wifi_down_mbps")
                wifi_up_mbps = phone_data.get("wifi_up_mbps")
                wifi_down_mbps = round(max(0.0, float(wifi_down_mbps)), 2) if wifi_down_mbps is not None else None
                wifi_up_mbps = round(max(0.0, float(wifi_up_mbps)), 2) if wifi_up_mbps is not None else None
                agent_source = phone_data.get("source")
                temperature_c = phone_data.get("temperature_c")
                temperature_c = (
                    round(float(temperature_c), 1)
                    if temperature_c is not None else None
                )
                temperature_source = str(phone_data.get("temperature_source") or "").strip()
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "error": "cpu und ram müssen Zahlen sein"}).encode("utf-8"))
                return

            with STATE_LOCK:
                GLOBAL_CPU = cpu_value
                GLOBAL_RAM = ram_value
                GLOBAL_WIFI_DOWN_MBPS = wifi_down_mbps
                GLOBAL_WIFI_UP_MBPS = wifi_up_mbps
                if temperature_c is not None and 0.0 <= temperature_c <= 100.0:
                    PHONE_TEMPERATURE_C = temperature_c
                if temperature_source:
                    PHONE_TEMPERATURE_SOURCE = temperature_source
                WIFI_INTERFACES_SOURCE = "Telefon-Agent"
                PHONE_METRICS_SOURCE = f"Telefon-Agent ({agent_source})" if agent_source else "Telefon-Agent"
                PHONE_METRICS_ERROR = None
                REMOTE_PHONE_METRICS_LAST_AT = time.time()
                # Drei Sekunden Schutz reichen für ein Agent-Intervall von
                # einer Sekunde und lassen bei Abbruch automatisch den
                # lokalen Telefonwert wieder übernehmen.
                REMOTE_PHONE_METRICS_UNTIL = time.time() + 3.0
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            return

        if path == "/admin/login":
            password = parsed_data.get("password", [""])[0]
            hashed = hashlib.sha256(password.encode()).hexdigest()
            if hashed == ADMIN_PASSWORD_HASH:
                session_id = hashlib.sha256(os.urandom(32)).hexdigest()
                with STATE_LOCK:
                    ADMIN_SESSION[session_id] = time.time()
                cookie = SimpleCookie()
                cookie["admin_session"] = session_id
                cookie["admin_session"]["path"] = "/"
                cookie["admin_session"]["max-age"] = 86400 * MAX_ADMIN_SESSION_DAYS

                self.send_response(302)
                self.send_header("Set-Cookie", cookie.output(header="").strip())
                self.send_header("Location", "/admin")
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header("Location", "/admin/login")
                self.end_headers()
            return

        cookie = SimpleCookie(self.headers.get("Cookie"))
        is_auth = False
        if "admin_session" in cookie:
            val = cookie["admin_session"].value
            with STATE_LOCK:
                if val in ADMIN_SESSION:
                    is_auth = True

        if not is_auth:
            self.send_response(302)
            self.send_header("Location", "/admin/login")
            self.end_headers()
            return

        if path == "/admin/update-settings":
            with STATE_LOCK:
                global MAINTENANCE_MODE, AUTO_BAN_ENABLED, AUTO_RESTART_ENABLED, SCHEDULED_RESTART_ENABLED, SCHEDULED_RESTART_INTERVAL
                global ALLOW_DESKTOP, ALLOW_MOBILE, ALLOW_CHROME, ALLOW_FIREFOX, ALLOW_SAFARI, ALLOW_EDGE, ALLOW_BOTS, BLOCK_VPN, REDIRECT_UNKNOWN
                global REDIRECT_COUNTRIES, REDIRECT_URL, MAX_REQUESTS_PER_IP, BAN_DURATION, THROTTLE_DELAY, RESTART_RPS_THRESHOLD, SERVER_LIMIT
                
                if "toggle_maint" in parsed_data:
                    MAINTENANCE_MODE = not MAINTENANCE_MODE
                elif "toggle_autoban" in parsed_data:
                    AUTO_BAN_ENABLED = not AUTO_BAN_ENABLED
                elif "toggle_autorestart" in parsed_data:
                    AUTO_RESTART_ENABLED = not AUTO_RESTART_ENABLED
                elif "toggle_schedrestart" in parsed_data:
                    SCHEDULED_RESTART_ENABLED = not SCHEDULED_RESTART_ENABLED
                elif "form_submitted" in parsed_data:
                    ALLOW_DESKTOP = "allow_desktop" in parsed_data
                    ALLOW_MOBILE = "allow_mobile" in parsed_data
                    ALLOW_CHROME = "allow_chrome" in parsed_data
                    ALLOW_FIREFOX = "allow_firefox" in parsed_data
                    ALLOW_SAFARI = "allow_safari" in parsed_data
                    ALLOW_EDGE = "allow_edge" in parsed_data
                    ALLOW_BOTS = "allow_bots" in parsed_data
                    BLOCK_VPN = "block_vpn" in parsed_data
                    REDIRECT_UNKNOWN = "redirect_unknown" in parsed_data
                    
                    if "redirect_countries" in parsed_data:
                        REDIRECT_COUNTRIES = set([c.strip().lower() for c in parsed_data["redirect_countries"][0].split(",") if c.strip()])
                    if "redirect_url" in parsed_data:
                        REDIRECT_URL = parsed_data["redirect_url"][0]
                        
                    if "max_ip_req" in parsed_data: MAX_REQUESTS_PER_IP = int(parsed_data["max_ip_req"][0])
                    if "ban_duration" in parsed_data: BAN_DURATION = int(parsed_data["ban_duration"][0])
                    if "throttle_delay" in parsed_data: THROTTLE_DELAY = float(parsed_data["throttle_delay"][0])
                    if "restart_rps_threshold" in parsed_data: RESTART_RPS_THRESHOLD = int(parsed_data["restart_rps_threshold"][0])
                    if "server_limit" in parsed_data: SERVER_LIMIT = int(parsed_data["server_limit"][0])
                    if "scheduled_restart_interval" in parsed_data: SCHEDULED_RESTART_INTERVAL = int(parsed_data["scheduled_restart_interval"][0])

                    if "ip_to_ban" in parsed_data and parsed_data["ip_to_ban"][0].strip():
                        BANNED_IPS.add(parsed_data["ip_to_ban"][0].strip())
                    if "ip_to_wl" in parsed_data and parsed_data["ip_to_wl"][0].strip():
                        WHITELISTED_IPS.add(parsed_data["ip_to_wl"][0].strip())
                    if "ip_to_redirect" in parsed_data and parsed_data["ip_to_redirect"][0].strip():
                        REDIRECT_IPS.add(parsed_data["ip_to_redirect"][0].strip())

            save_settings()
            self.send_response(302)
            self.send_header("Location", "/admin?tab=security")
            self.end_headers()
            return

        elif path == "/admin/start-timer-restart":
            sec = int(parsed_data.get("timer_seconds", ["10"])[0])
            trigger_timer_restart(sec)
            self.send_response(302)
            self.send_header("Location", "/admin?tab=timer")
            self.end_headers()
            return

        elif path == "/admin/restart-manual":
            trigger_restart()
            self.send_response(302)
            self.send_header("Location", "/admin?tab=security")
            self.end_headers()
            return

        elif path == "/admin/update-password":
            old_pw = parsed_data.get("old_password", [""])[0]
            new_pw = parsed_data.get("new_password", [""])[0]
            old_hash = hashlib.sha256(old_pw.encode()).hexdigest()
            with STATE_LOCK:
                if old_hash == ADMIN_PASSWORD_HASH:
                    ADMIN_PASSWORD_HASH = hashlib.sha256(new_pw.encode()).hexdigest()
                    save_settings()
            self.send_response(302)
            self.send_header("Location", "/admin?tab=account")
            self.end_headers()
            return

        self.send_response(302)
        self.send_header("Location", "/admin")
        self.end_headers()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        # Begrenze die Zahl gleichzeitiger Anfrage-Threads. Ohne Limit kann
        # eine Anfrageflut auf Android/Termux den Speicher erschöpfen und dazu
        # führen, dass Android den gesamten Python-Prozess mit SIGKILL beendet.
        self._worker_slots = threading.BoundedSemaphore(8)
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def process_request(self, request, client_address):
        # Bei voller Auslastung warten neue Verbindungen in der Socket-Queue,
        # statt weitere Python-Threads und deren Speicher zu erzeugen.
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()

    def handle_error(self, request, client_address):
        global HTTP_ERROR_LOG_LAST_AT
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionError, TimeoutError)):
            # Broken pipes and resets are expected when a client cancels a
            # request. Keep the server alive without flooding the terminal.
            return
        # Unexpected request failures remain visible, but repeated tracebacks
        # can flood Termux and waste CPU/storage. Emit at most one short line
        # every 15 seconds; status codes and responses are still recorded.
        now = time.monotonic()
        with HTTP_ERROR_LOG_LOCK:
            if now - HTTP_ERROR_LOG_LAST_AT < 15.0:
                return
            HTTP_ERROR_LOG_LAST_AT = now
        print(f"[HTTP-Fehler] Anfragefehler: {type(error).__name__}")

def run_phone_agent(server_url, token="", interval=1.0):
    """Sendet echte Android-/Termux-Werte an einen entfernten Server."""
    endpoint = server_url.rstrip("/") + "/api/phone-metrics"
    read_phone_cpu_percent()  # Referenzsample für die erste CPU-Messung
    print(f"[*] Telefon-Agent sendet Messwerte an {endpoint}")

    prev_rx, prev_tx, prev_time = None, None, None
    while True:
        time.sleep(max(1.0, interval))
        cpu_value, cpu_source = read_phone_cpu_percent()
        ram_value, ram_used_mb, ram_total_mb = read_phone_memory()
        temperature_c, temperature_source = read_phone_temperature()

        now_ts = time.time()
        rx_bytes, tx_bytes = read_phone_wifi_bytes()
        wifi_down_mbps = None
        wifi_up_mbps = None
        if rx_bytes is not None and tx_bytes is not None:
            if prev_rx is not None and prev_time is not None:
                dt = max(0.001, now_ts - prev_time)
                rx_delta = rx_bytes - prev_rx
                tx_delta = tx_bytes - prev_tx
                if rx_delta >= 0 and tx_delta >= 0:
                    wifi_down_mbps = round((rx_delta * 8) / dt / 1_000_000, 2)
                    wifi_up_mbps = round((tx_delta * 8) / dt / 1_000_000, 2)
            prev_rx, prev_tx, prev_time = rx_bytes, tx_bytes, now_ts
        else:
            prev_rx, prev_tx, prev_time = None, None, None

        if cpu_value is None or ram_value is None:
            continue

        payload = json.dumps({
            "cpu": cpu_value,
            "ram": ram_value,
            "ram_used_mb": ram_used_mb,
            "ram_total_mb": ram_total_mb,
            "temperature_c": temperature_c,
            "temperature_source": temperature_source,
            "wifi_down_mbps": wifi_down_mbps,
            "wifi_up_mbps": wifi_up_mbps,
            "source": cpu_source,
        }).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Phone-Metrics-Token": token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status != 200:
                    print(f"[WARNUNG] Telefon-Agent HTTP {response.status}")
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            print(f"[WARNUNG] Telefon-Agent konnte nicht senden: {error}")


def release_termux_wake_lock():
    global TERMUX_WAKE_LOCK_ACTIVE
    if not TERMUX_WAKE_LOCK_ACTIVE:
        return
    prefix = os.environ.get("PREFIX", "")
    unlock_command = os.path.join(prefix, "bin", "termux-wake-unlock")
    try:
        subprocess.run(
            [unlock_command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    TERMUX_WAKE_LOCK_ACTIVE = False


def enable_termux_wake_lock():
    """Keep Android's CPU awake while the server is running in Termux."""
    global TERMUX_WAKE_LOCK_ACTIVE
    prefix = os.environ.get("PREFIX", "")
    if not prefix or "com.termux" not in prefix:
        return

    lock_command = os.path.join(prefix, "bin", "termux-wake-lock")
    if not os.path.isfile(lock_command):
        print("[INFO] Termux-Wake-Lock fehlt. Optional: pkg install termux-api")
        return

    try:
        result = subprocess.run(
            [lock_command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        print("[INFO] Wake-Lock nicht verfügbar; Android-Energiesparen kann Termux pausieren.")
        return

    if result.returncode == 0:
        TERMUX_WAKE_LOCK_ACTIVE = True
        atexit.register(release_termux_wake_lock)
        print("[*] Termux-Wake-Lock aktiv (CPU bleibt während des Serverlaufs wach).")
    else:
        print("[INFO] Wake-Lock konnte nicht aktiviert werden; Termux ggf. von Akkuoptimierung ausnehmen.")


def run_server_forever():
    """Restart the listener after recoverable server-level errors."""
    retry_delay = 1
    while True:
        server = None
        started_at = time.monotonic()
        try:
            server = ThreadingHTTPServer((BIND_HOST, PORT), SecurityHandler)
            print(
                f"[*] Server läuft auf http://{BIND_HOST}:{PORT} "
                "(Live-Stats & begrenztes Threading aktiv)"
            )
            server.serve_forever(poll_interval=0.5)
            print("[WARNUNG] Server-Loop wurde unerwartet beendet.")
        except KeyboardInterrupt:
            print("\n[*] Server wird beendet.")
            break
        except Exception as error:
            print(
                f"[SERVER-FEHLER] {type(error).__name__}: {str(error)[:140]}. "
                f"Neustartversuch in {retry_delay} s."
            )
        finally:
            if server is not None:
                try:
                    server.server_close()
                except OSError:
                    pass

        if time.monotonic() - started_at >= 60:
            retry_delay = 1
        try:
            time.sleep(retry_delay)
        except KeyboardInterrupt:
            print("\n[*] Server wird beendet.")
            break
        retry_delay = min(30, retry_delay * 2)

    release_termux_wake_lock()


if __name__ == "__main__":
    if "--agent" in sys.argv:
        try:
            url_index = sys.argv.index("--agent") + 1
            agent_url = sys.argv[url_index]
        except (ValueError, IndexError):
            print("Verwendung: python script.py --agent http://SERVER:8080 [TOKEN]")
            sys.exit(2)
        agent_token = sys.argv[url_index + 1] if len(sys.argv) > url_index + 1 else PHONE_METRICS_TOKEN
        run_phone_agent(agent_url, agent_token)
        sys.exit(0)

    enable_termux_wake_lock()
    ensure_embedded_media()
    run_server_forever()
