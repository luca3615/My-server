from collections import defaultdict, deque
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

try:
    import psutil
except ImportError:
    psutil = None

PORT = int(os.environ.get("PORT", 8080))
START_TIME = time.time()
TOTAL_REQUESTS_COUNT = 0
REQUEST_TIMESTAMPS = deque()
WINDOW_SIZE = 1.0
RECENT_LOGS = deque(maxlen=50)
ip_request_counts = defaultdict(list)
country_stats = defaultdict(int)
status_code_stats = defaultdict(int)
user_agent_stats = defaultdict(int)
PEAK_RPS = 0
VPN_CACHE = {}

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
PHONE_METRICS_SOURCE = "Initialisiere Telefonmessung ..."
PHONE_METRICS_ERROR = None
CPU_METRIC_SIMULATED = False
CPU_PREVIOUS_TOTAL = None
CPU_PREVIOUS_IDLE = None
CPU_SAMPLES = deque(maxlen=5)
PROCESS_CPU_PREVIOUS_TICKS = None
PROCESS_CPU_PREVIOUS_WALL = None
SIMULATED_CPU_VALUE = 5.0
SIMULATED_PREVIOUS_REQUESTS = 0
SIMULATED_PREVIOUS_TIME = None
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
PHONE_METRICS_TOKEN = os.environ.get("PHONE_METRICS_TOKEN", "")

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
    for iface in interface_names:
        if not (_is_wireless_interface(iface) or _is_network_fallback_interface(iface)):
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
        if _is_wireless_interface(iface):
            wireless_rows.append(row)
        else:
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
    for iface, counter in counters.items():
        row = (iface, int(counter.bytes_recv), int(counter.bytes_sent))
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
    with STATE_LOCK:
        return (
            APPLICATION_RX_BYTES,
            APPLICATION_TX_BYTES,
            "Server-HTTP-Anwendungszähler",
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
        for line in lines:
            if ":" not in line:
                continue
            iface, data = line.split(":", 1)
            iface = iface.strip()
            fields = data.split()
            if len(fields) < 9:
                continue
            row = (iface, int(fields[0]), int(fields[8]))
            if _is_wireless_interface(iface):
                wireless_rows.append(row)
            elif _is_network_fallback_interface(iface):
                fallback_rows.append(row)

        selected_rows = wireless_rows or fallback_rows
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
            else f"Netzwerk-Fallback: {selected_names}"
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


def calculate_simulated_server_cpu():
    """Erzeugt eine sichtbare Serverlast aus der echten HTTP-Aktivität.

    Das ist absichtlich kein versteckter Hardwarewert: Die API kennzeichnet
    ihn als simuliert. Wenige Requests ergeben eine kleine Grundlast, viele
    Requests erhöhen den Wert geglättet bis maximal 100 Prozent.
    """
    global SIMULATED_CPU_VALUE
    global SIMULATED_PREVIOUS_REQUESTS, SIMULATED_PREVIOUS_TIME

    now = time.time()
    with STATE_LOCK:
        request_count = TOTAL_REQUESTS_COUNT

    if SIMULATED_PREVIOUS_TIME is None:
        SIMULATED_PREVIOUS_REQUESTS = request_count
        SIMULATED_PREVIOUS_TIME = now
        return round(SIMULATED_CPU_VALUE, 1)

    elapsed = max(0.25, now - SIMULATED_PREVIOUS_TIME)
    request_delta = max(0, request_count - SIMULATED_PREVIOUS_REQUESTS)
    requests_per_second = request_delta / elapsed
    SIMULATED_PREVIOUS_REQUESTS = request_count
    SIMULATED_PREVIOUS_TIME = now

    # 0 Requests ≈ 5 %, normaler Dashboard-Verkehr ≈ 15–30 %,
    # viele Requests steigen sichtbar bis 100 %. Die Glättung verhindert
    # hektische Sprünge bei einzelnen Requests.
    target = min(100.0, 5.0 + requests_per_second * 7.0)
    SIMULATED_CPU_VALUE = (
        SIMULATED_CPU_VALUE * 0.65
        + target * 0.35
    )
    return round(max(0.0, min(100.0, SIMULATED_CPU_VALUE)), 1)


def sys_monitor_worker():
    """Misst CPU/RAM/WLAN-Durchsatz des Telefons kontinuierlich und thread-sicher."""
    global GLOBAL_CPU, GLOBAL_RAM, PHONE_METRICS_SOURCE, PHONE_METRICS_ERROR
    global CPU_METRIC_SIMULATED
    global GLOBAL_WIFI_DOWN_MBPS, GLOBAL_WIFI_UP_MBPS
    global WIFI_PREV_RX, WIFI_PREV_TX, WIFI_PREV_TIME

    # Die CPU-Anzeige ist bewusst eine transparente Serverlast-Simulation,
    # weil Android die Gesamt-CPU für Termux nicht freigibt.
    while True:
        time.sleep(1.0)
        with STATE_LOCK:
            # Falls ein optionaler Telefon-Agent Daten an diesen Server
            # sendet, werden diese nicht sofort durch Serverwerte ersetzt.
            if time.time() < REMOTE_PHONE_METRICS_UNTIL:
                continue

        cpu_value = calculate_simulated_server_cpu()
        cpu_source = "Serverlast simuliert (HTTP-Anfragen)"
        ram_value, ram_used_mb, ram_total_mb = read_phone_memory()

        # psutil bleibt als Fallback für Systeme ohne lesbares /proc erhalten.
        if cpu_value is None or ram_value is None:
            try:
                if psutil is not None:
                    if cpu_value is None:
                        cpu_value = round(float(psutil.cpu_percent(interval=0.05)), 1)
                        cpu_source = "psutil"
                    if ram_value is None:
                        memory = psutil.virtual_memory()
                        ram_value = round(float(memory.percent), 1)
                        ram_used_mb = round(memory.used / 1024 / 1024, 1)
                        ram_total_mb = round(memory.total / 1024 / 1024, 1)
            except (OSError, AttributeError, ValueError):
                pass

        if cpu_value is not None:
            CPU_SAMPLES.append(cpu_value)
            cpu_value = round(sum(CPU_SAMPLES) / len(CPU_SAMPLES), 1)

        # WLAN-Durchsatz: Delta der kumulierten Byte-Zähler seit der letzten
        # Messung, umgerechnet in Mbit/s (echte Zeitdifferenz statt
        # angenommener 1.0s, damit es auch bei kurzen Verzögerungen stimmt).
        now_ts = time.time()
        rx_bytes, tx_bytes = read_phone_wifi_bytes()
        wifi_down_mbps = None
        wifi_up_mbps = None
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

        with STATE_LOCK:
            if cpu_value is not None:
                GLOBAL_CPU = cpu_value
            if ram_value is not None:
                GLOBAL_RAM = ram_value
            GLOBAL_WIFI_DOWN_MBPS = wifi_down_mbps
            GLOBAL_WIFI_UP_MBPS = wifi_up_mbps

            if cpu_value is not None or ram_value is not None:
                PHONE_METRICS_SOURCE = cpu_source or "Serverlast simuliert"
                PHONE_METRICS_ERROR = None
                CPU_METRIC_SIMULATED = True
            else:
                PHONE_METRICS_SOURCE = "Telefonmessung nicht verfügbar"
                PHONE_METRICS_ERROR = "Android hat keine lesbaren CPU-/RAM-Werte geliefert."

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

def cleanup_tracker():
    while True:
        time.sleep(300)
        now = time.time()
        with STATE_LOCK:
            expired = [ip for ip, data in ACTIVE_IP_TRACKER.items() if now - data.get("last_seen", 0) > 3600]
            for ip in expired:
                del ACTIVE_IP_TRACKER[ip]

cleanup_thread = threading.Thread(target=cleanup_tracker, daemon=True)
cleanup_thread.start()

BG_ANIMATION_JS = '''<canvas id="bgCanvas" style="position:fixed; top:0; left:0; width:100%; height:100%; z-index:-1; pointer-events:none; background:#020005;"></canvas>
<script>
(function() {
    const canvas = document.getElementById('bgCanvas');
    const ctx = canvas.getContext('2d');
    let width, height;

    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    const particles = [];
    const numParticles = 60;

    for(let i=0; i<numParticles; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 1.2,
            vy: (Math.random() - 0.5) * 1.2,
            size: Math.random() * 2.5 + 1,
            color: Math.random() > 0.5 ? 'rgba(192, 132, 252, ' : 'rgba(56, 189, 248, '
        });
    }

    let hueCounter = 0;

    function animate() {
        ctx.fillStyle = 'rgba(3, 0, 8, 0.25)';
        ctx.fillRect(0, 0, width, height);

        hueCounter += 0.01;

        for(let i=0; i<particles.length; i++) {
            let p = particles[i];
            p.x += p.vx;
            p.y += p.vy;

            if(p.x < 0) p.x = width;
            if(p.x > width) p.x = 0;
            if(p.y < 0) p.y = height;
            if(p.y > height) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = p.color + (0.4 + Math.sin(hueCounter + i) * 0.3) + ')';
            ctx.fill();

            for(let j=i+1; j<particles.length; j++) {
                let p2 = particles[j];
                let dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                if(dist < 120) {
                    ctx.strokeStyle = `rgba(168, 85, 247, ${(1 - dist/120) * 0.2})`;
                    ctx.lineWidth = 0.8;
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }
    animate();
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
        </div>
    </div>

    <script>
        function setOfflineState() {
            document.getElementById('status-pill').className = 'status-pill offline';
            document.getElementById('status-text').innerText = 'Offline';
        }

        function setOnlineState() {
            document.getElementById('status-pill').className = 'status-pill';
            document.getElementById('status-text').innerText = 'Operational';
        }

        function updateStats() {
            fetch('/api/stats', { mode: 'cors', cache: 'no-store' })
                .then(res => {
                    if (!res.ok) throw new Error();
                    return res.json();
                })
                .then(data => {
                    document.getElementById('total-req').innerText = data.total;
                    document.getElementById('current-rps').innerText = data.rps;
                    document.getElementById('blocked-rps').innerText = data.blocked_rps !== undefined ? data.blocked_rps : 0;

                    if (data.history && Array.isArray(data.history) && data.history.length > 0) {
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
        
        setInterval(updateStats, 500);
        updateStats();
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
                <h1>Live CPU / RAM (Handy/Server)</h1>
                <a href="/" class="back-btn">← Zurück</a>
            </div>
            
            <div class="stats-grid" style="grid-template-columns: 1fr 1fr;">
                <div class="stat-box"><div class="lbl">Serverlast (simuliert)</div><div class="val" id="live-cpu" style="color:var(--success);">warte ...</div></div>
                <div class="stat-box"><div class="lbl">RAM Auslastung (Telefon)</div><div class="val" id="live-ram" style="color:var(--success);">warte ...</div></div>
            </div>

            <div class="chart-container">
                <div class="chart-title">Serverlast + RAM Verlauf (letzte 60 Sekunden)</div>
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
<html lang="de"><head><meta charset="UTF-8"><title>Server Überlastet</title>
<style>
body { background: #030008; color: #fff; font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.card { background: rgba(20, 15, 35, 0.8); border: 1px solid rgba(251, 191, 36, 0.4); padding: 40px; border-radius: 20px; text-align: center; max-width: 400px; }
h2 { color: #fbbf24; margin-top: 0; }
</style></head>
<body>__BG_ANIMATION__<div class="card"><h2>⚠️ 503 Server Überlastet</h2><p style="color: #8b92b2;">Das maximale Anfragelimit wurde kurzzeitig überschritten. Bitte versuche es in wenigen Sekunden erneut.</p></div></body></html>'''.replace("__BG_ANIMATION__", BG_ANIMATION_JS)

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

    def log_message(self, format, *args):
        return

    def get_client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def do_GET(self):
        global TOTAL_REQUESTS_COUNT, PEAK_RPS
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)
        client_ip = self.get_client_ip()
        now = time.time()

        with STATE_LOCK:
            TOTAL_REQUESTS_COUNT += 1
            if TOTAL_REQUESTS_COUNT % 20 == 0:
                save_settings()

        if path == "/api/stats":
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
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            with STATE_LOCK:
                metrics = {
                    "cpu": GLOBAL_CPU,
                    "ram": GLOBAL_RAM,
                    "wifi_down_mbps": GLOBAL_WIFI_DOWN_MBPS,
                    "wifi_up_mbps": GLOBAL_WIFI_UP_MBPS,
                    "wifi_interfaces": WIFI_INTERFACES_SOURCE,
                    "cpu_simulated": CPU_METRIC_SIMULATED,
                    "source": PHONE_METRICS_SOURCE,
                    "error": PHONE_METRICS_ERROR,
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            self.wfile.write(json.dumps(metrics).encode("utf-8"))
            return

        with STATE_LOCK:
            if client_ip in BANNED_IPS:
                update_traffic_history("blocked")
                status_code_stats[403] += 1
                self.send_response(403)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(BANNED_HTML.replace("__REASON_TEXT__", "Deine IP wurde dauerhaft gesperrt.").encode("utf-8"))
                return

            if client_ip in TEMPORARY_BANS:
                if now < TEMPORARY_BANS[client_ip]:
                    update_traffic_history("blocked")
                    status_code_stats[429] += 1
                    remaining = int(TEMPORARY_BANS[client_ip] - now)
                    self.send_response(429)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(COOLDOWN_HTML.replace("__REMAINING__", str(max(1, remaining))).encode("utf-8"))
                    return
                else:
                    del TEMPORARY_BANS[client_ip]

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
                    self.send_response(429)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(COOLDOWN_HTML.replace("__REMAINING__", str(BAN_DURATION)).encode("utf-8"))
                    return

            if SERVER_LIMIT > 0 and len(REQUEST_TIMESTAMPS) > SERVER_LIMIT:
                update_traffic_history("overload")
                status_code_stats[503] += 1
                self.send_response(503)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(OVERLOAD_HTML.encode("utf-8"))
                return

            if BLOCK_VPN and is_ip_vpn_or_proxy(client_ip):
                update_traffic_history("blocked")
                status_code_stats[403] += 1
                self.send_response(403)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(VPN_WARN_HTML.encode("utf-8"))
                return

            if MAINTENANCE_MODE and not path.startswith("/admin"):
                status_code_stats[503] += 1
                self.send_response(503)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(MAINTENANCE_HTML.encode("utf-8"))
                return

        ua = self.headers.get("User-Agent", "Unbekannt")
        user_agent_stats[ua] += 1
        with STATE_LOCK:
            ACTIVE_IP_TRACKER[client_ip] = {"last_seen": now, "path": path}
            RECENT_LOGS.appendleft((time.strftime("%H:%M:%S"), client_ip, path, 200))

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
            with STATE_LOCK:
                for log in RECENT_LOGS:
                    logs_html += f"<tr><td>{log[0]}</td><td>{log[1]}</td><td>{log[2]}</td><td><span style='color:var(--success);'>{log[3]}</span></td></tr>"

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
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        global ADMIN_PASSWORD_HASH
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        parsed_data = urllib.parse.parse_qs(body)
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/phone-metrics":
            global GLOBAL_CPU, GLOBAL_RAM, PHONE_METRICS_SOURCE, PHONE_METRICS_ERROR, REMOTE_PHONE_METRICS_UNTIL
            global CPU_METRIC_SIMULATED
            global GLOBAL_WIFI_DOWN_MBPS, GLOBAL_WIFI_UP_MBPS, WIFI_INTERFACES_SOURCE
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
                WIFI_INTERFACES_SOURCE = "Telefon-Agent"
                PHONE_METRICS_SOURCE = f"Telefon-Agent ({agent_source})" if agent_source else "Telefon-Agent"
                PHONE_METRICS_ERROR = None
                CPU_METRIC_SIMULATED = False
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

    server = ThreadingHTTPServer(("0.0.0.0", PORT), SecurityHandler)
    print(f"[*] Server läuft auf Port {PORT} (Live-Stats & Threading aktiv)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server wird beendet.")
        sys.exit(0)

