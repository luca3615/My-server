from collections import defaultdict, deque
import http.server
import json
import os
import socketserver
import time
import urllib.parse
import urllib.request

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

# Traffic-Historie auf 60 Sekunden erweitert
TRAFFIC_HISTORY = deque([(0, 0, 0)] * 60, maxlen=60)
LAST_SEC_TIMESTAMP = int(time.time())
CURRENT_SEC_SUCCESS = 0
CURRENT_SEC_BLOCKED = 0
CURRENT_SEC_OVERLOAD = 0

SETTINGS_FILE = "database.json"
ADMIN_PASSWORD = "Luca123"

TEMPORARY_BANS = {}

default_settings = {
    "maintenance": False,
    "autoban": True,
    "max_ip_req": 2,
    "ban_duration": 10,
    "server_limit": 150,
    "throttle_delay": 2.0,
    "banned_ips": [],
    "whitelisted_ips": ["127.0.0.1", "::1"],
    "allow_desktop": True,
    "allow_mobile": True,
    "allow_chrome": True,
    "allow_firefox": True,
    "allow_safari": True,
    "allow_edge": True,
    "allow_bots": False,
}

MAINTENANCE_MODE = False
AUTO_BAN_ENABLED = True
MAX_REQUESTS_PER_IP = 2
BAN_DURATION = 10
SERVER_LIMIT = 150
THROTTLE_DELAY = 2.0
BANNED_IPS = set()
WHITELISTED_IPS = set()
ALLOW_DESKTOP = True
ALLOW_MOBILE = True
ALLOW_CHROME = True
ALLOW_FIREFOX = True
ALLOW_SAFARI = True
ALLOW_EDGE = True
ALLOW_BOTS = False


def load_settings():
  global MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, BAN_DURATION, SERVER_LIMIT, THROTTLE_DELAY, BANNED_IPS, WHITELISTED_IPS
  global ALLOW_DESKTOP, ALLOW_MOBILE, ALLOW_CHROME, ALLOW_FIREFOX, ALLOW_SAFARI, ALLOW_EDGE, ALLOW_BOTS

  if os.path.exists(SETTINGS_FILE):
    try:
      with open(SETTINGS_FILE, "r") as f:
        data = json.load(f)
        MAINTENANCE_MODE = data.get("maintenance", default_settings["maintenance"])
        AUTO_BAN_ENABLED = data.get("autoban", default_settings["autoban"])
        MAX_REQUESTS_PER_IP = data.get("max_ip_req", default_settings["max_ip_req"])
        BAN_DURATION = data.get("ban_duration", default_settings["ban_duration"])
        SERVER_LIMIT = data.get("server_limit", default_settings["server_limit"])
        THROTTLE_DELAY = data.get("throttle_delay", default_settings["throttle_delay"])
        BANNED_IPS = set(data.get("banned_ips", default_settings["banned_ips"]))
        
        loaded_wl = data.get("whitelisted_ips", default_settings["whitelisted_ips"])
        WHITELISTED_IPS = set(loaded_wl).union(set(default_settings["whitelisted_ips"]))

        ALLOW_DESKTOP = data.get("allow_desktop", default_settings["allow_desktop"])
        ALLOW_MOBILE = data.get("allow_mobile", default_settings["allow_mobile"])
        ALLOW_CHROME = data.get("allow_chrome", default_settings["allow_chrome"])
        ALLOW_FIREFOX = data.get("allow_firefox", default_settings["allow_firefox"])
        ALLOW_SAFARI = data.get("allow_safari", default_settings["allow_safari"])
        ALLOW_EDGE = data.get("allow_edge", default_settings["allow_edge"])
        ALLOW_BOTS = data.get("allow_bots", default_settings["allow_bots"])
        return
    except:
      pass
  
  MAINTENANCE_MODE = default_settings["maintenance"]
  AUTO_BAN_ENABLED = default_settings["autoban"]
  MAX_REQUESTS_PER_IP = default_settings["max_ip_req"]
  BAN_DURATION = default_settings["ban_duration"]
  SERVER_LIMIT = default_settings["server_limit"]
  THROTTLE_DELAY = default_settings["throttle_delay"]
  BANNED_IPS = set(default_settings["banned_ips"])
  WHITELISTED_IPS = set(default_settings["whitelisted_ips"])
  ALLOW_DESKTOP = default_settings["allow_desktop"]
  ALLOW_MOBILE = default_settings["allow_mobile"]
  ALLOW_CHROME = default_settings["allow_chrome"]
  ALLOW_FIREFOX = default_settings["allow_firefox"]
  ALLOW_SAFARI = default_settings["allow_safari"]
  ALLOW_EDGE = default_settings["allow_edge"]
  ALLOW_BOTS = default_settings["allow_bots"]
  save_settings()


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
        "whitelisted_ips": list(WHITELISTED_IPS),
        "allow_desktop": ALLOW_DESKTOP,
        "allow_mobile": ALLOW_MOBILE,
        "allow_chrome": ALLOW_CHROME,
        "allow_firefox": ALLOW_FIREFOX,
        "allow_safari": ALLOW_SAFARI,
        "allow_edge": ALLOW_EDGE,
        "allow_bots": ALLOW_BOTS,
    }
    with open(SETTINGS_FILE, "w") as f:
      json.dump(data, f, indent=4)
  except:
    pass


load_settings()


def update_traffic_history(req_type):
  global LAST_SEC_TIMESTAMP, CURRENT_SEC_SUCCESS, CURRENT_SEC_BLOCKED, CURRENT_SEC_OVERLOAD
  now_sec = int(time.time())
  if now_sec > LAST_SEC_TIMESTAMP:
    diff = now_sec - LAST_SEC_TIMESTAMP
    if diff >= 60:
      TRAFFIC_HISTORY.clear()
      for _ in range(60):
        TRAFFIC_HISTORY.append((0, 0, 0))
    else:
      for _ in range(diff - 1):
        TRAFFIC_HISTORY.append((0, 0, 0))
      TRAFFIC_HISTORY.append((CURRENT_SEC_SUCCESS, CURRENT_SEC_BLOCKED, CURRENT_SEC_OVERLOAD))
    CURRENT_SEC_SUCCESS = 0
    CURRENT_SEC_BLOCKED = 0
    CURRENT_SEC_OVERLOAD = 0
    LAST_SEC_TIMESTAMP = now_sec

  if req_type == "success":
    CURRENT_SEC_SUCCESS += 1
  elif req_type == "blocked":
    CURRENT_SEC_BLOCKED += 1
  elif req_type == "overload":
    CURRENT_SEC_OVERLOAD += 1


def get_geoip_and_country(ip):
  if (
      ip in ["127.0.0.1", "localhost", "::1"]
      or ip.startswith("192.168.")
      or ip.startswith("10.")
  ):
    return "Lokales Netzwerk", "Lokales Netzwerk"
  if ip in GEO_CACHE:
    return GEO_CACHE[ip]
  try:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=1.0) as response:
      data = json.loads(response.read().decode())
      if data.get("status") == "success":
        country = data.get("country", "Unbekannt")
        city = data.get("city", "Unbekannt")
        loc = f"{country} / {city}"
        GEO_CACHE[ip] = (loc, country)
        return loc, country
  except:
    pass
  return "Standort unbekannt", "Unbekannt"


def analyze_client_detailed(headers):
  ua_string = headers.get("User-Agent", "")
  ua = ua_string.lower()

  script_signatures = [
      "python",
      "requests",
      "urllib",
      "curl",
      "wget",
      "postman",
      "axios",
      "java/",
      "libwww",
  ]
  is_known_script = any(sig in ua for sig in script_signatures)
  is_bot_keyword = (
      "bot" in ua
      or "crawler" in ua
      or "spider" in ua
      or "slurp" in ua
      or "ia_archiver" in ua
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
  is_bot_or_script = is_known_script or is_bot_keyword or is_spoofed

  if is_bot_or_script:
    status_msg = f"🤖 Bot erkannt {'(Getarnt/Spoofed)' if is_spoofed else ''}"
  else:
    status_msg = f"Erlaubt ({device} - {browser})"

  return browser, device, is_bot_or_script, status_msg


def is_client_allowed(headers):
  browser, device, is_bot_or_script, _ = analyze_client_detailed(headers)
  if is_bot_or_script:
    return ALLOW_BOTS
  if device == "Mobile" and not ALLOW_MOBILE:
    return False
  if device == "Desktop" and not ALLOW_DESKTOP:
    return False
  if browser == "Google Chrome" and not ALLOW_CHROME:
    return False
  if browser == "Mozilla Firefox" and not ALLOW_FIREFOX:
    return False
  if browser == "Apple Safari" and not ALLOW_SAFARI:
    return False
  if browser == "Microsoft Edge" and not ALLOW_EDGE:
    return False
  return True


OVERLOAD_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>503 - Server Überlastet</title>
    <style>
        body { background: #090d16; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; text-align: center; padding: 15px; box-sizing: border-box; }
        .box { background: #131d31; border: 1px solid #ef4444; padding: 40px; border-radius: 20px; box-shadow: 0 20px 40px rgba(239, 68, 68, 0.2); max-width: 420px; width: 100%; }
        .icon { font-size: 50px; margin-bottom: 15px; display: inline-block; }
        h1 { font-size: 22px; margin-top: 0; margin-bottom: 10px; color: #ef4444; }
        p { color: #94a3b8; font-size: 13px; line-height: 1.5; margin: 0 0 20px 0; }
        .btn { background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-block; font-size: 13px; }
        .btn:hover { background: #2563eb; }
    </style>
</head>
<body>
    <div class="box">
        <div class="icon">🛡️</div>
        <h1>503 - Server Überlastet (DDoS Schutz)</h1>
        <p>Der Server verarbeitet aktuell extrem viele Anfragen und hat das Sicherheits-Limit erreicht. Bitte versuche es in wenigen Sekunden erneut.</p>
        <a href="/" class="btn">Erneut versuchen</a>
    </div>
</body>
</html>"""

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
            --danger: #ef4444;
            --warning: #f59e0b;
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
        
        .chart-wrapper { display: flex; align-items: stretch; background: #080d1a; border: 1px solid var(--border); border-radius: 12px; padding: 15px; margin-bottom: 12px; height: 110px; }
        .chart-axis { display: flex; flex-direction: column; justify-content: space-between; font-size: 10px; color: var(--text-muted); padding-right: 10px; text-align: right; min-width: 28px; user-select: none; }
        .chart-container { flex: 1; position: relative; height: 90px; border-left: 1px dashed var(--border); cursor: pointer; }
        
        .chart-title { font-size: 11px; font-weight: bold; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; display: flex; justify-content: space-between; }
        .legend { display: flex; gap: 15px; font-size: 11px; color: var(--text-muted); margin-bottom: 15px; justify-content: center; }
        .legend-item { display: flex; align-items: center; gap: 5px; }
        .legend-dot { width: 10px; height: 10px; border-radius: 3px; }

        .info-popup { background: #080d1a; border: 1px solid var(--primary); padding: 12px; border-radius: 10px; font-size: 12px; margin-bottom: 15px; display: none; align-items: center; justify-content: space-between; }
        .info-popup span { color: var(--text); }
        .info-popup b { color: var(--primary); }

        .admin-link { display: block; text-align: center; background: #1e293b; color: var(--text); padding: 12px; border-radius: 12px; text-decoration: none; font-weight: bold; font-size: 13px; border: 1px solid var(--border); margin-top: 15px; }
        .admin-link:hover { background: #26334d; border-color: var(--primary); }
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

            <div class="chart-title"><span>Live Traffic Verlauf (letzte 60 Sek. - Klick auf Diagramm für Details)</span><span id="api-status" style="color:var(--success);">● Verbunden</span></div>
            
            <div class="info-popup" id="info-popup">
                <span id="popup-text">Tippe auf eine Sekunde im Diagramm, um Details anzuzeigen.</span>
                <button onclick="document.getElementById('info-popup').style.display='none'" style="background:transparent; border:none; color:var(--text-muted); cursor:pointer; font-weight:bold;">✕</button>
            </div>

            <div class="legend">
                <div class="legend-item"><div class="legend-dot" style="background:var(--success);"></div> Erlaubt (200)</div>
                <div class="legend-item"><div class="legend-dot" style="background:var(--danger);"></div> Geblockt (403)</div>
                <div class="legend-item"><div class="legend-dot" style="background:var(--warning);"></div> Überlastet (503)</div>
            </div>
            <div class="chart-wrapper">
                <div class="chart-axis" id="chart-axis">
                    <span id="axis-max">10</span>
                    <span id="axis-mid">5</span>
                    <span id="axis-min">0</span>
                </div>
                <div class="chart-container" id="chart-click-area">
                    <svg id="line-chart" width="100%" height="100%" viewBox="0 0 600 90" preserveAspectRatio="none">
                        <path id="path-success" fill="none" stroke="#22c55e" stroke-width="2" d="M0,90 L600,90"></path>
                        <path id="path-blocked" fill="none" stroke="#ef4444" stroke-width="2" d="M0,90 L600,90"></path>
                        <path id="path-overload" fill="none" stroke="#f59e0b" stroke-width="2" d="M0,90 L600,90"></path>
                    </svg>
                </div>
            </div>

            <a href="/admin" class="admin-link">🔐 Zum Admin-Panel</a>
        </div>
    </div>
    <script>
        let latestHistoryData = [];

        function measurePing() {
            const start = performance.now();
            fetch('/api/stats?' + start, { method: 'HEAD', cache: 'no-store' })
                .then(() => {
                    const latency = Math.round(performance.now() - start);
                    document.getElementById('server-ping').innerText = latency + ' ms';
                })
                .catch(() => {
                    document.getElementById('server-ping').innerText = 'Error';
                });
        }
        setInterval(measurePing, 1000);
        measurePing();

        function updateStats() {
            fetch('/api/stats', { mode: 'cors', cache: 'no-store' })
                .then(res => {
                    if (!res.ok) throw new Error("Netzwerk-Antwort war nicht ok");
                    return res.json();
                })
                .then(data => {
                    document.getElementById('total-req').innerText = data.total;
                    document.getElementById('current-rps').innerText = data.rps;
                    document.getElementById('peak-rps').innerText = data.peak;
                    
                    if (data.history && Array.isArray(data.history)) {
                        latestHistoryData = data.history;
                        const allVals = [];
                        latestHistoryData.forEach(item => {
                            allVals.push(item[0], item[1], item[2]);
                        });
                        
                        const maxVal = allVals.length > 0 ? Math.max(...allVals, 5) : 5;
                        document.getElementById('axis-max').innerText = maxVal;
                        document.getElementById('axis-mid').innerText = Math.round(maxVal / 2);

                        const width = 600;
                        const height = 90;
                        const step = latestHistoryData.length > 1 ? width / (latestHistoryData.length - 1) : width;

                        let ptsSucc = [];
                        let ptsBlocked = [];
                        let ptsOverload = [];

                        latestHistoryData.forEach((item, index) => {
                            const x = index * step;
                            const ySucc = height - Math.min(height, (item[0] / maxVal) * height);
                            const yBlocked = height - Math.min(height, (item[1] / maxVal) * height);
                            const yOver = height - Math.min(height, (item[2] / maxVal) * height);

                            ptsSucc.push(`${x.toFixed(1)},${ySucc.toFixed(1)}`);
                            ptsBlocked.push(`${x.toFixed(1)},${yBlocked.toFixed(1)}`);
                            ptsOverload.push(`${x.toFixed(1)},${yOver.toFixed(1)}`);
                        });

                        document.getElementById('path-success').setAttribute('d', `M ` + ptsSucc.join(' L '));
                        document.getElementById('path-blocked').setAttribute('d', `M ` + ptsBlocked.join(' L '));
                        document.getElementById('path-overload').setAttribute('d', `M ` + ptsOverload.join(' L '));
                    }
                    
                    document.getElementById('api-status').style.color = 'var(--success)';
                    document.getElementById('api-status').innerText = '● Verbunden';
                })
                .catch(err => {
                    document.getElementById('api-status').style.color = 'var(--danger)';
                    document.getElementById('api-status').innerText = '● Verbindung gestört';
                });
        }
        
        // Intervall auf 1 Sekunde erhöht, um Überlastung/Rate-Limits im Browser zu verhindern
        setInterval(updateStats, 1000);
        updateStats();

        // Interaktives Anklicken des Diagramms
        document.getElementById('chart-click-area').addEventListener('click', function(e) {
            if(!latestHistoryData || latestHistoryData.length === 0) return;
            const rect = this.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const percentage = Math.max(0, Math.min(1, clickX / rect.width));
            
            const index = Math.round(percentage * (latestHistoryData.length - 1));
            if(index >= 0 && index < latestHistoryData.length) {
                const item = latestHistoryData[index];
                const secondsAgo = latestHistoryData.length - 1 - index;
                const popup = document.getElementById('info-popup');
                const popupText = document.getElementById('popup-text');
                
                popup.style.display = 'flex';
                popupText.innerHTML = `Vor <b>${secondsAgo}s</b>: <span style="color:var(--success);">Erlaubt: ${item[0]}</span> | <span style="color:var(--danger);">Geboesst/Geglockt: ${item[1]}</span> | <span style="color:var(--warning);">Überlastet: ${item[2]}</span>`;
            }
        });
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
        .checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 14px; font-size: 12px; }
        .checkbox-label { display: flex; align-items: center; gap: 8px; background: #131d31; padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border); cursor: pointer; }
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

            <a href="/admin?tab=security" class="btn-sec-link __TAB_SEC_BTN_ACTIVE__">⚙️ Sicherheit, Bot-Filter & Sperren</a>

            <!-- TAB 1: LIVE-LOGS -->
            <div class="tab-content __CONTENT_LOGS_ACTIVE__">
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Echte Live-Anfragen mit Live-Browser & Bot-Status:</div>
                <div style="max-height: 300px; overflow-y: auto;">
                    <table>
                        <tr><th>Zeit</th><th>IP</th><th>Pfad</th><th>Browser / Bot Status</th></tr>
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

            <!-- TAB 3: SICHERHEIT & BOT-FILTER -->
            <div class="tab-content __CONTENT_SECURITY_ACTIVE__">
                <form action="/admin/update-settings" method="POST">
                    <div class="section-box">
                        <label style="font-size: 11px; color: var(--text-muted); display:block; margin-bottom: 8px; font-weight: bold;">GERÄTE & BOT ZULASSUNG (ERLAUBEN / BLOCKIEREN)</label>
                        <div class="checkbox-grid">
                            <label class="checkbox-label"><input type="checkbox" name="allow_desktop" __CHECKED_DESKTOP__> Desktop Rechner</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_mobile" __CHECKED_MOBILE__> Mobile (Handys)</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_chrome" __CHECKED_CHROME__> Google Chrome</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_firefox" __CHECKED_FIREFOX__> Mozilla Firefox</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_safari" __CHECKED_SAFARI__> Apple Safari</label>
                            <label class="checkbox-label"><input type="checkbox" name="allow_edge" __CHECKED_EDGE__> Microsoft Edge</label>
                            <label class="checkbox-label" style="grid-column: span 2; border-color: rgba(239,68,68,0.4);"><input type="checkbox" name="allow_bots" __CHECKED_BOTS__> Bots / Crawler zulassen (Anti-Spoofing)</label>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 15px;">
                        <div class="section-box" style="margin-bottom:0;">
                            <div style="font-size: 12px; font-weight: bold; margin-bottom: 6px;">IP sperren:</div>
                            <input type="text" name="ip_to_ban" placeholder="z.B. 192.168.1.50" style="margin-bottom: 8px;">
                            
                            <div style="font-size: 12px; font-weight: bold; margin: 12px 0 6px 0;">Permanent gesperrt:</div>
                            <div style="max-height: 90px; overflow-y: auto;" id="banned-list-container">
                                __BANNED_LIST__
                            </div>
                            
                            <div style="font-size: 12px; font-weight: bold; margin: 12px 0 6px 0;">Temporär gesperrt (Auto-Ban):</div>
                            <div style="max-height: 90px; overflow-y: auto;" id="temp-banned-container">
                                __TEMP_BANNED_LIST__
                            </div>
                        </div>

                        <div class="section-box" style="margin-bottom:0;">
                            <div style="font-size: 12px; font-weight: bold; margin-bottom: 6px;">IP Whitelist:</div>
                            <input type="text" name="ip_to_wl" placeholder="z.B. 192.168.1.100" style="margin-bottom: 8px;">
                            
                            <div style="font-size: 12px; font-weight: bold; margin: 12px 0 6px 0;">Whitelisted:</div>
                            <div style="max-height: 110px; overflow-y: auto;" id="whitelist-container">
                                __WHITELIST_LIST__
                            </div>
                        </div>
                    </div>

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

                        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 11px;">Einstellungen & Filter speichern</button>
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
        function refreshAdminData() {
            fetch('/api/admin-data', { cache: 'no-store' })
                .then(res => {
                    if (!res.ok) throw new Error("Netzwerkfehler");
                    return res.json();
                })
                .then(data => {
                    if(document.getElementById('stat-200')) document.getElementById('stat-200').innerText = data.stat_200;
                    if(document.getElementById('stat-403')) document.getElementById('stat-403').innerText = data.stat_403;
                    if(document.getElementById('stat-503')) document.getElementById('stat-503').innerText = data.stat_503;
                    if(document.getElementById('curr-rps-val')) document.getElementById('curr-rps-val').innerText = data.current_rps;
                    if(document.getElementById('peak-rps-val')) document.getElementById('peak-rps-val').innerText = data.peak_rps;
                    if(document.getElementById('active-ips-val')) document.getElementById('active-ips-val').innerText = data.active_ips;

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
        setInterval(refreshAdminData, 1000);
    </script>
</body>
</html>"""


class FastTrafficHandler(http.server.BaseHTTPRequestHandler):

  def get_client_ip(self):
    xff = self.headers.get("X-Forwarded-For")
    if xff:
      return xff.split(",")[0].strip()
    return self.client_address[0]

  def do_HEAD(self):
    self.do_GET()

  def do_GET(self):
    global TOTAL_REQUESTS_COUNT, PEAK_RPS, MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, BAN_DURATION, THROTTLE_DELAY, SERVER_LIMIT, TEMPORARY_BANS

    client_ip = self.get_client_ip()
    now = time.time()

    expired_ips = [ip for ip, exp in TEMPORARY_BANS.items() if now > exp]
    for ip in expired_ips:
      del TEMPORARY_BANS[ip]

    parsed_path = urllib.parse.urlparse(self.path)
    path = parsed_path.path
    query_params = urllib.parse.parse_qs(parsed_path.query)

    # API-Statistiken ganz am Anfang abfangen (DDoS-resistent)
    if path == "/api/stats":
      REQUEST_TIMESTAMPS.append(now)
      while REQUEST_TIMESTAMPS and REQUEST_TIMESTAMPS[0] < now - WINDOW_SIZE:
        REQUEST_TIMESTAMPS.popleft()
      current_rps = len(REQUEST_TIMESTAMPS)
      if current_rps > PEAK_RPS:
        PEAK_RPS = current_rps

      data = {
          "total": TOTAL_REQUESTS_COUNT,
          "rps": current_rps,
          "peak": PEAK_RPS,
          "history": list(TRAFFIC_HISTORY),
      }
      self.send_response(200)
      self.send_header("Content-type", "application/json; charset=utf-8")
      self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
      self.end_headers()
      if self.command != "HEAD":
        self.wfile.write(json.dumps(data).encode("utf-8"))
      return

    is_api_or_admin = path.startswith("/api/") or path.startswith("/admin") or path == "/banned-redirect"

    def log_request(status_text):
      if not is_api_or_admin:
        geo_loc, country = get_geoip_and_country(client_ip)
        country_stats[country] += 1
        log_entry = {
            "path": path,
            "ua": status_text,
            "real_ip": client_ip,
            "geo": geo_loc,
            "time": time.strftime("%H:%M:%S", time.localtime()),
        }
        RECENT_LOGS.appendleft(log_entry)

    # Browser-Bann & Umleitung zu Google
    if not is_api_or_admin and client_ip not in WHITELISTED_IPS:
      if not is_client_allowed(self.headers):
        status_code_stats[403] += 1
        update_traffic_history("blocked")
        _, _, _, status_msg = analyze_client_detailed(self.headers)
        log_request(f"❌ Blockiert (Browser/Gerät): {status_msg}")
        self.send_response(303)
        self.send_header("Location", f"/banned-redirect?time={BAN_DURATION}")
        self.end_headers()
        return

      geo_loc, country = get_geoip_and_country(client_ip)
      if country in ["Unbekannt", "Standort unbekannt", "Lokales Netzwerk"]:
        status_code_stats[403] += 1
        update_traffic_history("blocked")
        log_request(f"🚫 Unbekanntes Herkunftsland/Proxy ({country}) - Umleitung zu Google")
        self.send_response(303)
        self.send_header("Location", f"/banned-redirect?time={BAN_DURATION}")
        self.end_headers()
        return

    REQUEST_TIMESTAMPS.append(now)
    while REQUEST_TIMESTAMPS and REQUEST_TIMESTAMPS[0] < now - WINDOW_SIZE:
      REQUEST_TIMESTAMPS.popleft()
    current_rps = len(REQUEST_TIMESTAMPS)
    if current_rps > PEAK_RPS:
      PEAK_RPS = current_rps

    if (
        not is_api_or_admin
        and current_rps > SERVER_LIMIT
        and client_ip not in WHITELISTED_IPS
    ):
      status_code_stats[503] += 1
      update_traffic_history("overload")
      log_request("⚠️ 503 Server Überlastet (DDoS Limit)")
      self.send_response(503)
      self.send_header("Content-type", "text/html; charset=utf-8")
      self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
      self.end_headers()
      if self.command != "HEAD":
        self.wfile.write(OVERLOAD_HTML.encode("utf-8"))
      return

    if client_ip not in WHITELISTED_IPS:
      if client_ip in BANNED_IPS or client_ip in TEMPORARY_BANS:
        status_code_stats[403] += 1
        update_traffic_history("blocked")
        log_request("🚫 403 IP Berechtigung entzogen / Bann")
        remaining_time = int(TEMPORARY_BANS.get(client_ip, now + BAN_DURATION) - now)
        if remaining_time < 1:
          remaining_time = BAN_DURATION
        self.send_response(303)
        self.send_header("Location", f"/banned-redirect?time={max(1, remaining_time)}")
        self.end_headers()
        return

    if client_ip not in WHITELISTED_IPS:
      timestamps = ip_request_counts[client_ip]
      timestamps[:] = [t for t in timestamps if t > now - 1.0]
      timestamps.append(now)

      if len(timestamps) > MAX_REQUESTS_PER_IP:
        if AUTO_BAN_ENABLED:
          TEMPORARY_BANS[client_ip] = now + BAN_DURATION
        status_code_stats[403] += 1
        update_traffic_history("blocked")
        log_request("⚡ 403 Rate Limit Überschritten (Auto-Ban)")
        self.send_response(303)
        self.send_header("Location", f"/banned-redirect?time={BAN_DURATION}")
        self.end_headers()
        return

    TOTAL_REQUESTS_COUNT += 1

    if path == "/banned-redirect":
      ban_time_param = query_params.get("time", [str(BAN_DURATION)])[0]
      try:
        ban_seconds = int(ban_time_param)
      except:
        ban_seconds = BAN_DURATION

      redirect_page = f"""<!DOCTYPE html>
      <html lang="de">
      <head>
          <meta charset="UTF-8">
          <title>Sicherheitssperre - Umleitung</title>
      </head>
      <body>
          <script>
              let timeLeft = {ban_seconds};
              window.location.replace("https://www.google.com");
              const interval = setInterval(() => {{
                  timeLeft--;
                  if(timeLeft <= 0) {{
                      clearInterval(interval);
                      window.location.href = "/";
                  }}
              }}, 1000);
          </script>
      </body>
      </html>"""
      self.send_response(200)
      self.send_header("Content-type", "text/html; charset=utf-8")
      self.end_headers()
      self.wfile.write(redirect_page.encode("utf-8"))
      return

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
            "temp_bans": temp_bans_list,
        }
        self.send_response(200)
        self.send_header("Content-type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        if self.command != "HEAD":
          self.wfile.write(json.dumps(admin_data).encode("utf-8"))
        return
      else:
        self.send_response(401)
        self.end_headers()
        return

    if path == "/":
      if MAINTENANCE_MODE:
        status_code_stats[503] += 1
        update_traffic_history("overload")
        self.send_response(503)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        if self.command != "HEAD":
          self.wfile.write(MAINTENANCE_HTML.encode("utf-8"))
        return

      _, _, _, status_msg = analyze_client_detailed(self.headers)
      log_request(f"✅ {status_msg}")
      status_code_stats[200] += 1
      update_traffic_history("success")

      self.send_response(200)
      self.send_header("Content-type", "text/html; charset=utf-8")
      self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
      self.end_headers()

      if self.command == "HEAD":
        return

      page = (
          PUBLIC_HTML.replace("__TOTAL_REQ__", str(TOTAL_REQUESTS_COUNT))
          .replace("__CURRENT_RPS__", str(current_rps))
          .replace("__PEAK_RPS__", str(PEAK_RPS))
      )
      self.wfile.write(page.encode("utf-8"))
      return

    if path == "/admin/logout":
      self.send_response(303)
      self.send_header(
          "Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
      )
      self.send_header("Location", "/admin")
      self.end_headers()
      return

    if path == "/admin":
      cookie = self.headers.get("Cookie", "")
      if f"session={ADMIN_PASSWORD}" in cookie:
        if not query_params.get("tab"):
          self.send_response(303)
          self.send_header("Location", "/admin?tab=logs")
          self.end_headers()
          return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        if self.command == "HEAD":
          return

        active_tab = query_params.get("tab", ["logs"])[0]

        tabs = ["logs", "geo", "security", "status"]
        tab_replacements = {}
        for t in tabs:
          is_active = t == active_tab
          tab_replacements[f"__TAB_{t.upper()}_ACTIVE__"] = (
              "active" if is_active else ""
          )
          tab_replacements[f"__CONTENT_{t.upper()}_ACTIVE__"] = (
              "active" if is_active else ""
          )

        tab_replacements["__TAB_SEC_BTN_ACTIVE__"] = (
            "active" if active_tab == "security" else ""
        )

        logs_html = ""
        for l in RECENT_LOGS:
          logs_html += (
              f"<tr><td>{l['time']}</td><td>{l['real_ip']}</td><td>{l['path']}</td><td>{l['ua']}</td></tr>"
          )
        if not logs_html:
          logs_html = "<tr><td colspan='4'>Noch keine Logs vorhanden.</td></tr>"

        geo_html = ""
        sorted_geo = sorted(
            country_stats.items(), key=lambda x: x[1], reverse=True
        )
        for country, count in sorted_geo:
          geo_html += f"<tr><td>🌍 {country}</td><td>{count} Aufrufe</td></tr>"
        if not geo_html:
          geo_html = (
              "<tr><td colspan='2'>Noch keine Daten vorhanden.</td></tr>"
          )

        banned_html = ""
        for ip in BANNED_IPS:
          banned_html += (
              f'<div class="ip-row"><span>{ip}</span><a'
              f' href="/admin/unban-ip?ip={ip}" class="btn btn-danger"'
              ' style="padding:2px 8px; font-size:10px;'
              ' text-decoration:none;">Freigeben</a></div>'
          )
        if not banned_html:
          banned_html = (
              '<div style="color:var(--text-muted); font-size:11px;">Keine'
              " permanenten Bans.</div>"
          )

        temp_banned_html = ""
        for ip, exp_time in list(TEMPORARY_BANS.items()):
          remaining = max(0, int(exp_time - time.time()))
          temp_banned_html += (
              f'<div class="ip-row"><span>{ip} <small'
              f' style="color:var(--warning);">({remaining}s übrig)</small></span><a'
              f' href="/admin/unban-temp?ip={ip}" class="btn btn-danger"'
              ' style="padding:2px 8px; font-size:10px;'
              ' text-decoration:none;">Freigeben</a></div>'
          )
        if not temp_banned_html:
          temp_banned_html = (
              '<div style="color:var(--text-muted); font-size:11px;">Keine'
              " aktiven temporären Bans.</div>"
          )

        whitelist_html = ""
        for ip in WHITELISTED_IPS:
          whitelist_html += f'<div class="ip-row"><span>{ip}</span>'
          if ip not in ["127.0.0.1", "::1"]:
            whitelist_html += (
                f'<a href="/admin/unremove-wl?ip={ip}" class="btn btn-danger"'
                ' style="padding:2px 8px; font-size:10px;'
                ' text-decoration:none;">Entfernen</a>'
            )
          else:
            whitelist_html += (
                '<span style="font-size:10px;'
                ' color:var(--text-muted);">System</span>'
            )
          whitelist_html += "</div>"
        if not whitelist_html:
          whitelist_html = (
              '<div style="color:var(--text-muted); font-size:11px;">Keine'
              " whitelisted IPs.</div>"
          )

        maint_text = "AN" if MAINTENANCE_MODE else "AUS"
        maint_btn_class = "btn-warning" if MAINTENANCE_MODE else "btn-primary"

        autoban_text = "AN" if AUTO_BAN_ENABLED else "AUS"
        autoban_btn_class = "btn-primary" if AUTO_BAN_ENABLED else "btn-danger"

        page = ADMIN_PANEL_HTML
        for k, v in tab_replacements.items():
          page = page.replace(k, v)

        page = (
            page.replace("__LOGS_TABLE__", logs_html)
            .replace("__GEO_TABLE__", geo_html)
            .replace("__BANNED_LIST__", banned_html)
            .replace("__TEMP_BANNED_LIST__", temp_banned_html)
            .replace("__WHITELIST_LIST__", whitelist_html)
            .replace("__MAINT_TEXT__", maint_text)
            .replace("__MAINT_BTN_CLASS__", maint_btn_class)
            .replace("__AUTOBAN_TEXT__", autoban_text)
            .replace("__AUTOBAN_BTN_CLASS__", autoban_btn_class)
            .replace("__MAX_IP_REQ__", str(MAX_REQUESTS_PER_IP))
            .replace("__BAN_DURATION__", str(BAN_DURATION))
            .replace("__THROTTLE_DELAY__", str(THROTTLE_DELAY))
            .replace("__SERVER_LIMIT__", str(SERVER_LIMIT))
            .replace("__STAT_200__", str(status_code_stats[200]))
            .replace("__STAT_403__", str(status_code_stats[403]))
            .replace("__STAT_503__", str(status_code_stats[503]))
            .replace("__CURRENT_RPS__", str(current_rps))
            .replace("__PEAK_RPS__", str(PEAK_RPS))
            .replace("__ACTIVE_IPS__", str(len(ip_request_counts)))
            .replace("__CHECKED_DESKTOP__", "checked" if ALLOW_DESKTOP else "")
            .replace("__CHECKED_MOBILE__", "checked" if ALLOW_MOBILE else "")
            .replace("__CHECKED_CHROME__", "checked" if ALLOW_CHROME else "")
            .replace("__CHECKED_FIREFOX__", "checked" if ALLOW_FIREFOX else "")
            .replace("__CHECKED_SAFARI__", "checked" if ALLOW_SAFARI else "")
            .replace("__CHECKED_EDGE__", "checked" if ALLOW_EDGE else "")
            .replace("__CHECKED_BOTS__", "checked" if ALLOW_BOTS else "")
        )

        self.wfile.write(page.encode("utf-8"))
        return
      else:
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        if self.command != "HEAD":
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
        self.send_header("Location", "/admin?tab=security")
        self.end_headers()
        return

    if path == "/admin/unban-temp":
      cookie = self.headers.get("Cookie", "")
      if f"session={ADMIN_PASSWORD}" in cookie:
        ip_to_unban = query_params.get("ip", [""])[0]
        if ip_to_unban in TEMPORARY_BANS:
          del TEMPORARY_BANS[ip_to_unban]
        self.send_response(303)
        self.send_header("Location", "/admin?tab=security")
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
        self.send_header("Location", "/admin?tab=security")
        self.end_headers()
        return

    if MAINTENANCE_MODE:
      status_code_stats[503] += 1
      update_traffic_history("overload")
      log_request("⚙️ 503 Wartungsmodus aktiv")
      self.send_response(503)
      self.send_header("Content-type", "text/html; charset=utf-8")
      self.end_headers()
      if self.command != "HEAD":
        self.wfile.write(MAINTENANCE_HTML.encode("utf-8"))
      return

    geo_loc, country = get_geoip_and_country(client_ip)
    country_stats[country] += 1
    status_code_stats[200] += 1
    update_traffic_history("success")

    _, _, _, status_msg = analyze_client_detailed(self.headers)
    log_request(f"✅ {status_msg}")

    self.send_response(200)
    self.send_header("Content-type", "text/html; charset=utf-8")
    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
    self.end_headers()

    if self.command == "HEAD":
      return

    self.wfile.write(PUBLIC_HTML.encode("utf-8"))

  def do_POST(self):
    global MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, BAN_DURATION, THROTTLE_DELAY, SERVER_LIMIT
    global ALLOW_DESKTOP, ALLOW_MOBILE, ALLOW_CHROME, ALLOW_FIREFOX, ALLOW_SAFARI, ALLOW_EDGE, ALLOW_BOTS

    parsed_path = urllib.parse.urlparse(self.path)
    path = parsed_path.path

    if path == "/admin/login":
      content_length = int(self.headers.get("Content-Length", 0))
      post_data = self.rfile.read(content_length).decode("utf-8")
      params = urllib.parse.parse_qs(post_data)
      password = params.get("password", [""])[0]

      if password == ADMIN_PASSWORD:
        self.send_response(303)
        self.send_header("Set-Cookie", f"session={ADMIN_PASSWORD}; Path=/")
        self.send_header("Location", "/admin?tab=logs")
        self.end_headers()
      else:
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b"Falsches Passwort!")
      return

    cookie = self.headers.get("Cookie", "")
    if f"session={ADMIN_PASSWORD}" in cookie:
      content_length = int(self.headers.get("Content-Length", 0))
      post_data = self.rfile.read(content_length).decode("utf-8")
      params = urllib.parse.parse_qs(post_data)

      if path == "/admin/update-settings":
        ip_ban = params.get("ip_to_ban", [""])[0].strip()
        if ip_ban:
          BANNED_IPS.add(ip_ban)

        ip_wl = params.get("ip_to_wl", [""])[0].strip()
        if ip_wl:
          WHITELISTED_IPS.add(ip_wl)

        if "toggle_maint" in params:
          MAINTENANCE_MODE = not MAINTENANCE_MODE
        if "toggle_autoban" in params:
          AUTO_BAN_ENABLED = not AUTO_BAN_ENABLED

        ALLOW_DESKTOP = "allow_desktop" in params
        ALLOW_MOBILE = "allow_mobile" in params
        ALLOW_CHROME = "allow_chrome" in params
        ALLOW_FIREFOX = "allow_firefox" in params
        ALLOW_SAFARI = "allow_safari" in params
        ALLOW_EDGE = "allow_edge" in params
        ALLOW_BOTS = "allow_bots" in params

        try:
          if "max_ip_req" in params:
            MAX_REQUESTS_PER_IP = int(params["max_ip_req"][0])
          ...

