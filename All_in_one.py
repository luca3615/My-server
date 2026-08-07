import http.server
import socketserver
import time
import json
import os
import urllib.request
from collections import deque, defaultdict
import urllib.parse

PORT = int(os.environ.get("PORT", 8080))
START_TIME = time.time()
TOTAL_REQUESTS_COUNT = 0
REQUEST_TIMESTAMPS = deque()
WINDOW_SIZE = 1.0
RECENT_LOGS = deque(maxlen=50) 
ip_request_counts = defaultdict(list)
country_stats = defaultdict(int)
status_code_stats = defaultdict(int)
PEAK_RPS = 0
GEO_CACHE = {}

TRAFFIC_HISTORY = deque([0] * 30, maxlen=30)
LAST_SEC_TIMESTAMP = int(time.time())
CURRENT_SEC_COUNT = 0

SETTINGS_FILE = "settings.json"
ADMIN_PASSWORD = "Luca123"

# Speichert temporäre Sperren als Dictionary: {ip: ablauf_timestamp}
TEMPORARY_BANS = {}

default_settings = {
    "maintenance": False,
    "autoban": True,
    "max_ip_req": 2,
    "ban_duration": 10,
    "server_limit": 150,
    "throttle_delay": 2.0,
    "banned_ips": [],
    "whitelisted_ips": ["127.0.0.1", "::1"]
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
                for key in default_settings:
                    if key not in data:
                        data[key] = default_settings[key]
                return data
        except:
            pass
    return default_settings.copy()

def save_settings():
    try:
        data = {
            "maintenance": MAINTENANCE_MODE,
            "autoban": AUTO_BAN_ENABLED,
            "max_ip_req": MAX_REQUESTS_PER_IP,
            "ban_duration": BAN_DURATION,
            "server_limit": SERVER_LIMIT,
            "throttle_delay": THROTTLE_DELAY,
            "banned_ips": list(BANNED_IPS),
            "whitelisted_ips": list(WHITELISTED_IPS)
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except:
        pass

config_data = load_settings()
MAINTENANCE_MODE = config_data["maintenance"]
AUTO_BAN_ENABLED = config_data["autoban"]
MAX_REQUESTS_PER_IP = config_data["max_ip_req"]
BAN_DURATION = config_data["ban_duration"]
SERVER_LIMIT = config_data["server_limit"]
THROTTLE_DELAY = config_data["throttle_delay"]
BANNED_IPS = set(config_data["banned_ips"])
WHITELISTED_IPS = set(config_data["whitelisted_ips"])

def update_traffic_history():
    global LAST_SEC_TIMESTAMP, CURRENT_SEC_COUNT
    now_sec = int(time.time())
    if now_sec > LAST_SEC_TIMESTAMP:
        diff = now_sec - LAST_SEC_TIMESTAMP
        if diff >= 30:
            TRAFFIC_HISTORY.clear()
            for _ in range(30):
                TRAFFIC_HISTORY.append(0)
        else:
            for _ in range(diff - 1):
                TRAFFIC_HISTORY.append(0)
            TRAFFIC_HISTORY.append(CURRENT_SEC_COUNT)
        CURRENT_SEC_COUNT = 0
        LAST_SEC_TIMESTAMP = now_sec
    CURRENT_SEC_COUNT += 1

def get_geoip_and_country(ip):
    if ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("192.168.") or ip.startswith("10."):
        return "Lokales Netzwerk", "Lokaler Server"
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.0) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                country = data.get('country', 'Unbekannt')
                city = data.get('city', 'Unbekannt')
                loc = f"{country} / {city}"
                GEO_CACHE[ip] = (loc, country)
                return loc, country
    except:
        pass
    return "Standort unbekannt", "Unbekannt"

def parse_user_agent(ua_string):
    ua = ua_string.lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        device = "📱 Handy"
    elif "bot" in ua or "crawler" in ua or "spider" in ua:
        device = "🤖 Bot"
    else:
        device = "💻 Desktop"
    
    if "chrome" in ua and "edge" not in ua: browser = "Chrome"
    elif "firefox" in ua: browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua: browser = "Safari"
    elif "edge" in ua: browser = "Edge"
    elif "bot" in ua: browser = "Bot/Crawler"
    else: browser = "Web-Client"
    
    return f"{device} ({browser})"

PUBLIC_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Traffic Monitor & DDoS Schutz</title>
    <style>
        :root {
            --bg: #090d16;
            --card-bg: #131d31;
            --border: #1e293b;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --success: #22c55e;
            --accent: #06b6d4;
        }
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; min-height: 100vh; box-sizing: border-box; }
        .container { width: 100%; max-width: 700px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); padding: 25px; border-radius: 20px; box-shadow: 0 20px 40px -15px rgba(0,0,0,0.7); margin-bottom: 20px; }
        h1 { font-size: 20px; margin-top: 0; background: linear-gradient(to right, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; display: flex; align-items: center; justify-content: space-between; }
        p { color: var(--text-muted); font-size: 13px; line-height: 1.5; margin-bottom: 20px; }
        .status-pill { display: inline-flex; align-items: center; gap: 8px; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: var(--success); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }
        .stat-box { background: #080d1a; border: 1px solid var(--border); padding: 12px; border-radius: 12px; text-align: center; }
        .stat-box .val { font-size: 15px; font-weight: bold; color: var(--primary); margin-top: 4px; }
        .stat-box .lbl { font-size: 10px; color: var(--text-muted); text-transform: uppercase; }
        
        .chart-wrapper { display: flex; align-items: stretch; background: #080d1a; border: 1px solid var(--border); border-radius: 12px; padding: 15px; margin-bottom: 15px; height: 120px; }
        .chart-axis { display: flex; flex-direction: column; justify-content: space-between; font-size: 10px; color: var(--text-muted); padding-right: 10px; text-align: right; min-width: 28px; user-select: none; }
        .chart-container { flex: 1; display: flex; align-items: flex-end; gap: 4px; position: relative; overflow: hidden; height: 100%; border-left: 1px dashed var(--border); padding-left: 8px; }
        .bar { flex: 1; background: var(--primary); border-radius: 3px 3px 0 0; transition: height 0.3s ease; min-height: 4px; opacity: 0.8; position: relative; }
        .bar:hover { opacity: 1; background: var(--accent); }
        .chart-title { font-size: 11px; font-weight: bold; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Live Traffic Monitor <span class="status-pill">● Online & Geschützt</span></h1>
            <p>Dein Server analysiert und schützt den Datenverkehr in Echtzeit.</p>
            
            <div class="stats-grid">
                <div class="stat-box"><div class="lbl">Aufrufe</div><div class="val" id="total-req">__TOTAL_REQ__</div></div>
                <div class="stat-box"><div class="lbl">Anfragen/s</div><div class="val" id="current-rps">__CURRENT_RPS__</div></div>
                <div class="stat-box"><div class="lbl">Peak RPS</div><div class="val" id="peak-rps">__PEAK_RPS__</div></div>
                <div class="stat-box"><div class="lbl">Server Ping</div><div class="val" id="server-ping">-- ms</div></div>
            </div>

            <div class="chart-title"><span>Live Anfragen Verlauf (letzte 30 Sek.)</span><span id="api-status" style="color:var(--success);">● Verbunden</span></div>
            <div class="chart-wrapper">
                <div class="chart-axis" id="chart-axis">
                    <span id="axis-max">10</span>
                    <span id="axis-mid">5</span>
                    <span id="axis-min">0</span>
                </div>
                <div class="chart-container" id="chart">
                    __CHART_BARS__
                </div>
            </div>
        </div>
    </div>
    <script>
        function updateStats() {
            fetch('/api/stats', { mode: 'cors' })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('total-req').innerText = data.total;
                    document.getElementById('current-rps').innerText = data.rps;
                    document.getElementById('peak-rps').innerText = data.peak;
                    
                    const chart = document.getElementById('chart');
                    let barsHtml = '';
                    const maxVal = data.history.length > 0 ? Math.max(...data.history, 3) : 3;
                    
                    document.getElementById('axis-max').innerText = maxVal;
                    document.getElementById('axis-mid').innerText = Math.round(maxVal / 2);

                    data.history.forEach(val => {
                        let heightPct = Math.round((val / maxVal) * 100);
                        if (heightPct < 5) heightPct = 5;
                        barsHtml += `<div class="bar" style="height: ${heightPct}%;" title="${val} Anfragen"></div>`;
                    });
                    chart.innerHTML = barsHtml;
                })
                .catch(err => {});
        }
        setInterval(updateStats, 500);
    </script>
</body>
</html>"""

MAINTENANCE_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wartungsarbeiten</title>
    <style>
        body { background: #000000; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; text-align: center; padding: 15px; box-sizing: border-box; }
        .box { background: #0b0f19; border: 1px solid #1e293b; padding: 40px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.9); max-width: 400px; width: 100%; }
        .gear { font-size: 55px; margin-bottom: 20px; display: inline-block; animation: spin 4s linear infinite; }
        h1 { font-size: 22px; margin-top: 0; margin-bottom: 10px; color: #38bdf8; }
        p { color: #94a3b8; font-size: 13px; line-height: 1.5; margin: 0; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="box">
        <div class="gear">⚙️</div>
        <h1>Wartungsarbeiten</h1>
        <p>Das System wird aktuell gewartet. Wir sind in Kürze wieder da!</p>
    </div>
</body>
</html>"""

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anmeldung</title>
    <style>
        body { margin: 0; background: #05070a; color: white; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; overflow: hidden; }
        .stars { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; background: radial-gradient(ellipse at bottom, #1B2735 0%, #090A0F 100%); }
        .star { position: absolute; background: white; border-radius: 50%; opacity: 0.5; animation: twinkle var(--duration) infinite; }
        @keyframes twinkle { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
        .login-card { background: rgba(19, 29, 49, 0.85); backdrop-filter: blur(12px); border: 1px solid #3b82f6; padding: 35px 25px; border-radius: 20px; width: 100%; max-width: 320px; box-shadow: 0 20px 40px rgba(0,0,0,0.7), 0 0 20px rgba(59, 130, 246, 0.2); text-align: center; box-sizing: border-box; }
        .login-icon { font-size: 40px; margin-bottom: 15px; }
        h3 { margin: 0 0 5px 0; font-size: 20px; color: #fff; }
        p { color: #94a3b8; font-size: 12px; margin: 0 0 20px 0; }
        .input-group { text-align: left; margin-bottom: 15px; }
        label { display: block; font-size: 11px; color: #94a3b8; margin-bottom: 6px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
        input { width: 100%; padding: 12px; background: #090d16; border: 1px solid #1e293b; color: #fff; border-radius: 10px; box-sizing: border-box; font-size: 14px; outline: none; transition: border-color 0.2s; }
        input:focus { border-color: #3b82f6; }
        button { width: 100%; padding: 12px; background: #3b82f6; border: none; color: #fff; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 14px; transition: background 0.2s, transform 0.1s; margin-top: 5px; }
        button:hover { background: #2563eb; }
        button:active { transform: scale(0.98); }
    </style>
</head>
<body>
    <div class="stars" id="stars"></div>
    <div class="login-card">
        <div class="login-icon">🔐</div>
        <h3>Geschützter Bereich</h3>
        <p>Bitte Zugangsdaten eingeben</p>
        <form method="POST" action="/admin/login">
            <div class="input-group">
                <label>Passwort</label>
                <input type="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit">Anmelden</button>
        </form>
    </div>
    <script>
        for(let i=0; i<80; i++) {
            let s = document.createElement('div');
            s.className = 'star';
            s.style.width = s.style.height = Math.random() * 3 + 'px';
            s.style.left = Math.random() * 100 + '%';
            s.style.top = Math.random() * 100 + '%';
            s.style.setProperty('--duration', (Math.random() * 3 + 2) + 's');
            document.getElementById('stars').appendChild(s);
        }
    </script>
</body>
</html>"""

ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin-Steuerung</title>
    <style>
        :root {
            --bg: #070b14;
            --card-bg: #111a2e;
            --border: #1e293b;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --danger: #ef4444;
            --success: #22c55e;
            --warning: #f59e0b;
        }
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 12px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; box-sizing: border-box; }
        .container { width: 100%; max-width: 650px; margin-top: 10px; margin-bottom: 30px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); padding: 22px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
        .header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 18px; font-weight: bold; }
        .sub-header { font-size: 12px; color: var(--text-muted); margin-bottom: 18px; display: flex; justify-content: space-between; }
        .badge-aktiv { background: rgba(34, 197, 94, 0.12); border: 1px solid rgba(34, 197, 94, 0.3); color: var(--success); padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        
        .nav-tabs { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; background: #080d1a; padding: 6px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 12px; }
        .tab-btn { padding: 10px 6px; text-align: center; font-size: 12px; font-weight: 600; color: var(--text-muted); background: transparent; border: none; border-radius: 8px; cursor: pointer; text-decoration: none; transition: 0.2s; display: block; }
        .tab-btn.active { background: var(--primary); color: #fff; box-shadow: 0 4px 12px rgba(59,130,246,0.4); }
        
        .btn-sec-link { background: #1e293b; color: var(--text); padding: 12px; text-align: center; border-radius: 12px; margin-bottom: 18px; display: block; text-decoration: none; font-weight: bold; font-size: 13px; border: 1px solid var(--border); transition: 0.2s; }
        .btn-sec-link:hover { background: #26334d; border-color: var(--primary); }
        .btn-sec-link.active { background: var(--primary); color: white; border-color: var(--primary); }

        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: monospace; }
        th, td { padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: left; }
        th { color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; }
        
        .btn { padding: 9px 14px; border-radius: 8px; font-weight: bold; cursor: pointer; border: none; font-size: 12px; color: #fff; text-decoration: none; display: inline-block; text-align: center; transition: 0.2s; }
        .btn-primary { background: var(--primary); }
        .btn-primary:hover { background: #2563eb; }
        .btn-danger { background: var(--danger); }
        .btn-danger:hover { background: #dc2626; }
        .btn-warning { background: var(--warning); color: #000; }
        .btn-success { background: var(--success); }
        
        input[type="text"], input[type="number"] { width: 100%; background: #080d1a; border: 1px solid var(--border); color: #fff; padding: 11px; border-radius: 8px; box-sizing: border-box; margin-bottom: 10px; font-size: 13px; outline: none; transition: border-color 0.2s; }
        input[type="text"]:focus, input[type="number"]:focus { border-color: var(--primary); }
        
        .ip-row { display: flex; justify-content: space-between; align-items: center; background: #080d1a; border: 1px solid var(--border); padding: 10px 14px; border-radius: 10px; margin-bottom: 8px; font-family: monospace; font-size: 12px; word-break: break-all; }
        .stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 18px; }
        .stat-card { background: #080d1a; border: 1px solid var(--border); padding: 14px; border-radius: 12px; text-align: center; }
        .stat-card .val { font-size: 18px; font-weight: bold; color: var(--primary); margin-top: 6px; }
        .stat-card .lbl { font-size: 11px; color: var(--text-muted); font-weight: 600; }
        .section-box { background: #080d1a; padding: 15px; border-radius: 14px; border: 1px solid var(--border); margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header-row">
                <span>Admin-Steuerung</span>
                <span class="badge-aktiv">● Aktiv</span>
            </div>
            <div class="sub-header">
                <span>Authentifiziert</span>
                <a href="/" style="color:var(--primary); text-decoration:none;">← Zur Startseite</a>
            </div>

            <div class="nav-tabs">
                <a href="/admin?tab=logs" class="tab-btn __TAB_LOGS_ACTIVE__">Logs</a>
                <a href="/admin?tab=geo" class="tab-btn __TAB_GEO_ACTIVE__">Geo-Top</a>
                <a href="/admin?tab=status" class="tab-btn __TAB_STATUS_ACTIVE__">Status</a>
            </div>

            <a href="/admin?tab=security" class="btn-sec-link __TAB_SEC_BTN_ACTIVE__">⚙️ Sicherheit, Sperren & Whitelist verwalten</a>

            <!-- TAB 1: LIVE-LOGS -->
            <div class="tab-content __CONTENT_LOGS_ACTIVE__">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Echte Live-Anfragen mit IP-Adressen:</div>
                <div style="max-height: 300px; overflow-y: auto;">
                    <table>
                        <tr><th>Zeit</th><th>IP-Adresse</th><th>Standort</th><th>Pfad</th><th>Gerät</th></tr>
                        __LOGS_TABLE__
                    </table>
                </div>
            </div>

            <!-- TAB 2: GEO-TOP -->
            <div class="tab-content __CONTENT_GEO_ACTIVE__">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Top Länder-Herkunft (Traffic Verteilung):</div>
                <div style="max-height: 300px; overflow-y: auto;">
                    <table>
                        <tr><th>Land</th><th>Aufrufe</th></tr>
                        __GEO_TABLE__
                    </table>
                </div>
            </div>

            <!-- TAB 3: SICHERHEIT & WL -->
            <div class="tab-content __CONTENT_SECURITY_ACTIVE__">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 15px;">
                    <div class="section-box" style="margin-bottom:0;">
                        <form action="/admin/ban-ip" method="POST">
                            <div style="font-size: 12px; font-weight: bold; margin-bottom: 6px;">IP sperren:</div>
                            <input type="text" name="ip" placeholder="z.B. 192.168.1.50" required style="margin-bottom: 8px;">
                            <button type="submit" class="btn btn-danger" style="width: 100%; padding: 7px;">Sperren</button>
                        </form>
                        <div style="font-size: 12px; font-weight: bold; margin: 12px 0 6px 0;">Permanent gesperrt:</div>
                        <div style="max-height: 110px; overflow-y: auto;" id="banned-list-container">
                            __BANNED_LIST__
                        </div>
                        
                        <div style="font-size: 12px; font-weight: bold; margin: 12px 0 6px 0;">Temporär gesperrt (Auto-Ban):</div>
                        <div style="max-height: 110px; overflow-y: auto;" id="temp-banned-container">
                            __TEMP_BANNED_LIST__
                        </div>
                    </div>

                    <div class="section-box" style="margin-bottom:0;">
                        <form action="/admin/whitelist-ip" method="POST">
                            <div style="font-size: 12px; font-weight: bold; margin-bottom: 6px;">IP Whitelist:</div>
                            <input type="text" name="ip" placeholder="z.B. 192.168.1.100" required style="margin-bottom: 8px;">
                            <button type="submit" class="btn btn-success" style="width: 100%; padding: 7px;">Erlauben</button>
                        </form>
                        <div style="font-size: 12px; font-weight: bold; margin: 12px 0 6px 0;">Whitelisted:</div>
                        <div style="max-height: 110px; overflow-y: auto;" id="whitelist-container">
                            __WHITELIST_LIST__
                        </div>
                    </div>
                </div>

                <form action="/admin/update-settings" method="POST">
                    <div class="section-box">
                        <div style="margin-bottom: 14px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 6px; font-weight: bold;">SYSTEM-STEUERUNG</label>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                                <button type="submit" name="toggle_maint" value="1" class="btn __MAINT_BTN_CLASS__" style="width:100%;">Wartung: __MAINT_TEXT__</button>
                                <button type="submit" name="toggle_autoban" value="1" class="btn __AUTOBAN_BTN_CLASS__" style="width:100%;">Auto-Ban: __AUTOBAN_TEXT__</button>
                            </div>
                        </div>

                        <div style="margin-bottom: 14px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 6px; font-weight: bold;">SCHWELLENWERTE & DAUER</label>
                            <input type="number" name="max_ip_req" value="__MAX_IP_REQ__" placeholder="Max Anfragen pro Sek." required style="margin-bottom:8px;">
                            <input type="number" name="ban_duration" value="__BAN_DURATION__" placeholder="Auto-Ban Dauer in Sek. (z.B. 10)" required style="margin-bottom:8px;">
                            <input type="number" step="0.1" name="throttle_delay" value="__THROTTLE_DELAY__" placeholder="Verzögerung in Sek." required style="margin-bottom:0;">
                        </div>

                        <div style="margin-bottom: 14px;">
                            <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 6px; font-weight: bold;">GLOBALES SERVER-LIMIT</label>
                            <input type="number" name="server_limit" value="__SERVER_LIMIT__" placeholder="Max. RPS Schwelle" required style="margin-bottom:0;">
                        </div>

                        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 11px;">Einstellungen speichern</button>
                    </div>
                </form>
            </div>

            <!-- TAB 4: STATUS -->
            <div class="tab-content __CONTENT_STATUS_ACTIVE__">
                <div class="stats-row">
                    <div class="stat-card"><div class="lbl">200 OK</div><div class="val" style="color:var(--success);" id="stat-200">__STAT_200__</div></div>
                    <div class="stat-card"><div class="lbl">403</div><div class="val" style="color:var(--danger);" id="stat-403">__STAT_403__</div></div>
                    <div class="stat-card"><div class="lbl">503</div><div class="val" style="color:var(--warning);" id="stat-503">__STAT_503__</div></div>
                </div>
                <div style="font-size: 13px; margin-bottom: 10px; font-weight: bold;">Server-Echtzeit Status:</div>
                <div class="ip-row"><span>Aktuelle RPS</span><span style="color:var(--primary);" id="curr-rps-val">__CURRENT_RPS__</span></div>
                <div class="ip-row"><span>Peak RPS</span><span style="color:var(--primary);" id="peak-rps-val">__PEAK_RPS__</span></div>
                <div class="ip-row"><span>Aktive IP-Tracker</span><span style="color:var(--primary);" id="active-ips-val">__ACTIVE_IPS__</span></div>
            </div>

            <div style="margin-top: 15px;">
                <a href="/admin/logout" class="btn btn-danger" style="width: 100%; text-align: center; display: block; box-sizing: border-box; padding: 11px;">Abmelden</a>
            </div>
        </div>
    </div>
    <script>
        // Automatisches Live-Update alle 0.5 Sekunden (500ms) für das Admin-Panel
        function refreshAdminData() {
            fetch('/api/admin-data')
                .then(res => res.json())
                .then(data => {
                    // Status Zähler aktualisieren (200, 403, 503, RPS etc.)
                    if(document.getElementById('stat-200')) document.getElementById('stat-200').innerText = data.stat_200;
                    if(document.getElementById('stat-403')) document.getElementById('stat-403').innerText = data.stat_403;
                    if(document.getElementById('stat-503')) document.getElementById('stat-503').innerText = data.stat_503;
                    if(document.getElementById('curr-rps-val')) document.getElementById('curr-rps-val').innerText = data.current_rps;
                    if(document.getElementById('peak-rps-val')) document.getElementById('peak-rps-val').innerText = data.peak_rps;
                    if(document.getElementById('active-ips-val')) document.getElementById('active-ips-val').innerText = data.active_ips;

                    // Temporäre Bans dynamisch aktualisieren
                    const tempContainer = document.getElementById('temp-banned-container');
                    if(tempContainer) {
                        if(data.temp_bans.length === 0) {
                            tempContainer.innerHTML = '<div style="color:var(--text-muted); font-size:11px;">Keine aktiven temporären Bans.</div>';
                        } else {
                            let html = '';
                            data.temp_bans.forEach(b => {
                                html += `<div class="ip-row"><span>${b.ip} <small style="color:var(--warning);">(${b.remaining}s übrig)</small></span><a href="/admin/unban-temp?ip=${b.ip}" class="btn btn-danger" style="padding:2px 8px; font-size:10px; text-decoration:none;">Freigeben</a></div>`;
                            });
                            tempContainer.innerHTML = html;
                        }
                    }
                })
                .catch(err => {});
        }
        setInterval(refreshAdminData, 500);
    </script>
</body>
</html>"""

class FastTrafficHandler(http.server.BaseHTTPRequestHandler):
    def get_client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def do_GET(self):
        global TOTAL_REQUESTS_COUNT, PEAK_RPS, MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, BAN_DURATION, THROTTLE_DELAY, SERVER_LIMIT, TEMPORARY_BANS
        
        client_ip = self.get_client_ip()
        now = time.time()
        
        # Abgelaufene temporäre Bans automatisch bereinigen
        expired_ips = [ip for ip, exp in TEMPORARY_BANS.items() if now > exp]
        for ip in expired_ips:
            del TEMPORARY_BANS[ip]

        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query_params = urllib.parse.parse_qs(parsed_path.query)

        # Prüfung ob permanent oder temporär gebannt
        if client_ip not in WHITELISTED_IPS:
            if client_ip in BANNED_IPS or client_ip in TEMPORARY_BANS:
                status_code_stats[403] += 1
                self.send_error(403, "Access Denied - Banned / Rate Limited")
                return

        # Rate Limiting Check
        if client_ip not in WHITELISTED_IPS:
            timestamps = ip_request_counts[client_ip]
            timestamps[:] = [t for t in timestamps if t > now - 1.0]
            timestamps.append(now)
            
            if len(timestamps) > MAX_REQUESTS_PER_IP:
                if AUTO_BAN_ENABLED:
                    TEMPORARY_BANS[client_ip] = now + BAN_DURATION
                status_code_stats[403] += 1
                self.send_error(403, "Rate Limit Exceeded - Temporary Ban")
                return

        TOTAL_REQUESTS_COUNT += 1
        update_traffic_history()

        REQUEST_TIMESTAMPS.append(now)
        while REQUEST_TIMESTAMPS and REQUEST_TIMESTAMPS[0] < now - WINDOW_SIZE:
            REQUEST_TIMESTAMPS.popleft()
        
        current_rps = len(REQUEST_TIMESTAMPS)
        if current_rps > PEAK_RPS:
            PEAK_RPS = current_rps

        # API Endpunkt für Live-Statistiken der Startseite
        if path == "/api/stats":
            data = {
                "total": TOTAL_REQUESTS_COUNT,
                "rps": current_rps,
                "peak": PEAK_RPS,
                "history": list(TRAFFIC_HISTORY)
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        # API Endpunkt für das 0.5s Live-Update im Admin-Panel
        if path == "/api/admin-data":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                temp_bans_list = []
                for ip, exp_time in list(TEMPORARY_BANS.items()):
                    remaining = max(0, int(exp_time - time.time()))
                    temp_bans_list.append({"ip": ip, "remaining": remaining})

                admin_data = {
                    "stat_200": status_code_stats[200],
                    "stat_403": status_code_stats[403],
                    "stat_503": status_code_stats[503],
                    "current_rps": current_rps,
                    "peak_rps": PEAK_RPS,
                    "active_ips": len(ip_request_counts),
                    "temp_bans": temp_bans_list
                }
                self.send_response(200)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps(admin_data).encode("utf-8"))
                return
            else:
                self.send_response(401)
                self.end_headers()
                return

        if path == "/":
            if MAINTENANCE_MODE:
                self.send_response(503)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(MAINTENANCE_HTML.encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            max_val = max(TRAFFIC_HISTORY) if TRAFFIC_HISTORY and max(TRAFFIC_HISTORY) > 0 else 3
            chart_html = ""
            for val in TRAFFIC_HISTORY:
                height_pct = int((val / max_val) * 100)
                if height_pct < 5: 
                    height_pct = 5
                chart_html += f'<div class="bar" style="height: {height_pct}%;" title="{val} Anfragen"></div>'

            page = PUBLIC_HTML.replace("__TOTAL_REQ__", str(TOTAL_REQUESTS_COUNT))\
                              .replace("__CURRENT_RPS__", str(current_rps))\
                              .replace("__PEAK_RPS__", str(PEAK_RPS))\
                              .replace("__CHART_BARS__", chart_html)
            self.wfile.write(page.encode("utf-8"))
            return

        if path == "/admin/logout":
            self.send_response(303)
            self.send_header('Set-Cookie', 'session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.send_header('Location', '/admin')
            self.end_headers()
            return

        if path == "/admin":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                if not query_params.get("tab"):
                    self.send_response(303)
                    self.send_header('Location', '/admin?tab=logs')
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                
                active_tab = query_params.get("tab", ["logs"])[0]
                
                tabs = ["logs", "geo", "security", "status"]
                tab_replacements = {}
                for t in tabs:
                    is_active = (t == active_tab)
                    tab_replacements[f"__TAB_{t.upper()}_ACTIVE__"] = "active" if is_active else ""
                    tab_replacements[f"__CONTENT_{t.upper()}_ACTIVE__"] = "active" if is_active else ""

                tab_replacements["__TAB_SEC_BTN_ACTIVE__"] = "active" if active_tab == "security" else ""

                logs_html = ""
                for l in RECENT_LOGS:
                    logs_html += f"<tr><td>{l['time']}</td><td>{l['real_ip']}</td><td>{l['geo']}</td><td>{l['path']}</td><td>{l['ua']}</td></tr>"
                if not logs_html:
                    logs_html = "<tr><td colspan='5'>Noch keine Logs vorhanden.</td></tr>"
                
                geo_html = ""
                sorted_geo = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)
                for country, count in sorted_geo:
                    geo_html += f"<tr><td>🌍 {country}</td><td>{count} Aufrufe</td></tr>"
                if not geo_html:
                    geo_html = "<tr><td colspan='2'>Noch keine Daten vorhanden.</td></tr>"

                banned_html = ""
                for ip in BANNED_IPS:
                    banned_html += f'<div class="ip-row"><span>{ip}</span><a href="/admin/unban-ip?ip={ip}" class="btn btn-danger" style="padding:2px 8px; font-size:10px; text-decoration:none;">Freigeben</a></div>'
                if not banned_html:
                    banned_html = '<div style="color:var(--text-muted); font-size:11px;">Keine permanenten Bans.</div>'

                temp_banned_html = ""
                for ip, exp_time in list(TEMPORARY_BANS.items()):
                    remaining = max(0, int(exp_time - time.time()))
                    temp_banned_html += f'<div class="ip-row"><span>{ip} <small style="color:var(--warning);">({remaining}s übrig)</small></span><a href="/admin/unban-temp?ip={ip}" class="btn btn-danger" style="padding:2px 8px; font-size:10px; text-decoration:none;">Freigeben</a></div>'
                if not temp_banned_html:
                    temp_banned_html = '<div style="color:var(--text-muted); font-size:11px;">Keine aktiven temporären Bans.</div>'

                whitelist_html = ""
                for ip in WHITELISTED_IPS:
                    whitelist_html += f'<div class="ip-row"><span>{ip}</span>'
                    if ip not in ["127.0.0.1", "::1"]:
                        whitelist_html += f'<a href="/admin/unremove-wl?ip={ip}" class="btn btn-danger" style="padding:2px 8px; font-size:10px; text-decoration:none;">Entfernen</a>'
                    else:
                        whitelist_html += '<span style="font-size:10px; color:var(--text-muted);">System</span>'
                    whitelist_html += '</div>'
                if not whitelist_html:
                    whitelist_html = '<div style="color:var(--text-muted); font-size:11px;">Keine whitelisted IPs.</div>'

                maint_text = "AN" if MAINTENANCE_MODE else "AUS"
                maint_btn_class = "btn-warning" if MAINTENANCE_MODE else "btn-primary"
                
                autoban_text = "AN" if AUTO_BAN_ENABLED else "AUS"
                autoban_btn_class = "btn-primary" if AUTO_BAN_ENABLED else "btn-danger"

                page = ADMIN_PANEL_HTML
                for k, v in tab_replacements.items():
                    page = page.replace(k, v)

                page = page.replace("__LOGS_TABLE__", logs_html)\
                           .replace("__GEO_TABLE__", geo_html)\
                           .replace("__BANNED_LIST__", banned_html)\
                           .replace("__TEMP_BANNED_LIST__", temp_banned_html)\
                           .replace("__WHITELIST_LIST__", whitelist_html)\
                           .replace("__MAINT_TEXT__", maint_text)\
                           .replace("__MAINT_BTN_CLASS__", maint_btn_class)\
                           .replace("__AUTOBAN_TEXT__", autoban_text)\
                           .replace("__AUTOBAN_BTN_CLASS__", autoban_btn_class)\
                           .replace("__MAX_IP_REQ__", str(MAX_REQUESTS_PER_IP))\
                           .replace("__BAN_DURATION__", str(BAN_DURATION))\
                           .replace("__THROTTLE_DELAY__", str(THROTTLE_DELAY))\
                           .replace("__SERVER_LIMIT__", str(SERVER_LIMIT))\
                           .replace("__STAT_200__", str(status_code_stats[200]))\
                           .replace("__STAT_403__", str(status_code_stats[403]))\
                           .replace("__STAT_503__", str(status_code_stats[503]))\
                           .replace("__CURRENT_RPS__", str(current_rps))\
                           .replace("__PEAK_RPS__", str(PEAK_RPS))\
                           .replace("__ACTIVE_IPS__", str(len(ip_request_counts)))

                self.wfile.write(page.encode("utf-8"))
                return
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(ADMIN_LOGIN_HTML.encode("utf-8"))
                return

        if path == "/admin/unban-ip":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                ip_to_unban = query_params.get("ip", [""])[0]
                if ip_to_unban in BANNED_IPS:
                    BANNED_IPS.remove(ip_to_unban)
                    save_settings()
                self.send_response(303)
                self.send_header('Location', '/admin?tab=security')
                self.end_headers()
                return

        if path == "/admin/unban-temp":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                ip_to_unban = query_params.get("ip", [""])[0]
                if ip_to_unban in TEMPORARY_BANS:
                    del TEMPORARY_BANS[ip_to_unban]
                self.send_response(303)
                self.send_header('Location', '/admin?tab=security')
                self.end_headers()
                return

        if path == "/admin/unremove-wl":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                ip_to_wl = query_params.get("ip", [""])[0]
                if ip_to_wl in WHITELISTED_IPS and ip_to_wl not in ["127.0.0.1", "::1"]:
                    WHITELISTED_IPS.remove(ip_to_wl)
                    save_settings()
                self.send_response(303)
                self.send_header('Location', '/admin?tab=security')
                self.end_headers()
                return

        if MAINTENANCE_MODE:
            self.send_response(503)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(MAINTENANCE_HTML.encode("utf-8"))
            return

        if current_rps > SERVER_LIMIT:
            status_code_stats[503] += 1
            self.send_error(503, "Server Overloaded")
            return

        geo_loc, country = get_geoip_and_country(client_ip)
        country_stats[country] += 1
        status_code_stats[200] += 1
        
        ua_string = self.headers.get("User-Agent", "Unknown")
        parsed_ua = parse_user_agent(ua_string)
        
        log_entry = {
            "path": path,
            "ua": parsed_ua,
            "real_ip": client_ip,
            "geo": geo_loc,
            "time": time.strftime("%H:%M:%S", time.localtime())
        }
        RECENT_LOGS.appendleft(log_entry)

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PUBLIC_HTML.encode("utf-8"))

    def do_POST(self):
        global MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, BAN_DURATION, THROTTLE_DELAY, SERVER_LIMIT
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/admin/login":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            password = params.get('password', [''])[0]

            if password == ADMIN_PASSWORD:
                self.send_response(303)
                self.send_header('Set-Cookie', f'session={ADMIN_PASSWORD}; Path=/')
                self.send_header('Location', '/admin?tab=logs')
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Falsches Passwort!")
            return

        cookie = self.headers.get("Cookie", "")
        if f"session={ADMIN_PASSWORD}" in cookie:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            if path == "/admin/ban-ip":
                ip_to_ban = params.get("ip", [""])[0].strip()
                if ip_to_ban:
                    BANNED_IPS.add(ip_to_ban)
                    save_settings()
            elif path == "/admin/whitelist-ip":
                ip_to_wl = params.get("ip", [""])[0].strip()
                if ip_to_wl:
                    WHITELISTED_IPS.add(ip_to_wl)
                    save_settings()
            elif path == "/admin/update-settings":
                if "toggle_maint" in params:
                    MAINTENANCE_MODE = not MAINTENANCE_MODE
                if "toggle_autoban" in params:
                    AUTO_BAN_ENABLED = not AUTO_BAN_ENABLED
                try:
                    if "max_ip_req" in params:
                        MAX_REQUESTS_PER_IP = int(params["max_ip_req"][0])
                    if "ban_duration" in params:
                        BAN_DURATION = int(params["ban_duration"][0])
                    if "throttle_delay" in params:
                        THROTTLE_DELAY = float(params["throttle_delay"][0])
                    if "server_limit" in params:
                        SERVER_LIMIT = int(params["server_limit"][0])
                except:
                    pass
                save_settings()

            self.send_response(303)
            self.send_header('Location', '/admin?tab=security')
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    with ThreadedHTTPServer(("", PORT), FastTrafficHandler) as httpd:
        print(f"High-Performance Threaded Server läuft auf Port {PORT}")
        httpd.serve_forever()

