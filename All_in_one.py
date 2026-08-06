import http.server
import socketserver
import time
import json
import os
import urllib.request
from collections import deque, defaultdict
import urllib.parse

PORT = 8080
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

SETTINGS_FILE = "settings.json"
ADMIN_PASSWORD = "Eichenstrasse12"

default_settings = {
    "maintenance": False,
    "autoban": True,
    "max_ip_req": 2,
    "server_limit": 450,
    "throttle_delay": 2.0,
    "banned_ips": ["103.43.191.71", "175.6.75.144", "91.108.232.130", "213.207.198.254", "102.132.16.46"],
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
            "server_limit": SERVER_LIMIT,
            "throttle_delay": THROTTLE_DELAY,
            "banned_ips": list(BANNED_IPS),
            "whitelisted_ips": list(WHITELISTED_IPS)
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except:
        pass

def get_geoip_and_country(ip):
    if ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("192.168.") or ip.startswith("10."):
        return "Lokales Netzwerk", "Lokaler Server"
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.5) as response:
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

config_data = load_settings()
MAINTENANCE_MODE = config_data["maintenance"]
AUTO_BAN_ENABLED = config_data["autoban"]
MAX_REQUESTS_PER_IP = config_data["max_ip_req"]
SERVER_LIMIT = config_data["server_limit"]
THROTTLE_DELAY = config_data["throttle_delay"]
BANNED_IPS = set(config_data["banned_ips"])
WHITELISTED_IPS = set(config_data["whitelisted_ips"])
ARTIFICIAL_DELAY = 0.05

PUBLIC_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Traffic Monitor</title>
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
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; min-height: 100vh; box-sizing: border-box; justify-content: center; }
        .container { width: 100%; max-width: 600px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); padding: 30px; border-radius: 20px; box-shadow: 0 20px 40px -15px rgba(0,0,0,0.7); margin-bottom: 20px; text-align: center; }
        h1 { font-size: 22px; margin-top: 0; background: linear-gradient(to right, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        p { color: var(--text-muted); font-size: 13px; line-height: 1.5; margin-bottom: 25px; }
        .status-pill { display: inline-flex; align-items: center; gap: 8px; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.2); color: var(--success); padding: 6px 14px; border-radius: 50px; font-size: 12px; font-weight: 600; }
        .dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Live Traffic Monitor</h1>
            <p>Dein Server läuft stabil und sicher in der Cloud.</p>
            <div class="status-pill">
                <div class="dot"></div> System Online
            </div>
        </div>
    </div>
</body>
</html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin-Steuerung</title>
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
        }
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 15px; display: flex; flex-direction: column; align-items: center; min-height: 100vh; box-sizing: border-box; }
        .container { width: 100%; max-width: 650px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); margin-bottom: 20px; }
        .header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 14px; font-weight: bold; }
        .sub-info { font-size: 11px; color: var(--text-muted); margin-bottom: 15px; display: flex; justify-content: space-between; }
        .badge-aktiv { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: var(--success); padding: 3px 10px; border-radius: 20px; font-size: 11px; }
        .nav-tabs { display: grid; grid-template-columns: repeat(6, 1fr); gap: 4px; margin-bottom: 20px; background: #0f172a; padding: 4px; border-radius: 10px; }
        .tab-btn { background: transparent; color: var(--text-muted); border: none; padding: 8px 2px; font-size: 11px; font-weight: 600; cursor: pointer; border-radius: 6px; text-align: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .tab-btn.active { background: var(--primary); color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 15px; }
        .stat-box { background: #0f172a; border: 1px solid var(--border); padding: 12px; border-radius: 10px; text-align: center; }
        .stat-box .val { font-size: 18px; font-weight: bold; color: var(--primary); margin-top: 5px; }
        .stat-box .lbl { font-size: 11px; color: var(--text-muted); }
        .log-box { background: #070a12; border: 1px solid var(--border); border-radius: 8px; padding: 10px; height: 220px; overflow-y: auto; font-family: monospace; font-size: 11px; margin-bottom: 15px; }
        .log-item { padding: 6px 0; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; }
        .btn { background: var(--primary); color: white; border: none; padding: 8px 14px; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 12px; width: 100%; text-align: center; display: inline-block; box-sizing: border-box; text-decoration: none;}
        .btn-danger { background: var(--danger); }
        .btn-warning { background: var(--warning); color: #000; }
        .btn-success { background: var(--success); }
        input[type="text"], input[type="password"], input[type="number"] { width: 100%; background: #070a12; border: 1px solid var(--border); padding: 10px; border-radius: 8px; color: white; box-sizing: border-box; margin-bottom: 10px; font-size: 12px; }
        .action-row { display: flex; gap: 8px; margin-top: 10px; }
        .list-item { background: #0f172a; border: 1px solid var(--border); padding: 8px 12px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-size: 12px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header-row">
                <span>Admin-Steuerung</span>
                <span class="badge-aktiv">● Aktiv</span>
            </div>
            <div class="sub-info">
                <span id="session-timeout">Session-Timeout in 10:00 min</span>
                <span id="uptime">Uptime: 0m 0s</span>
            </div>

            <div class="nav-tabs">
                <button class="tab-btn active" onclick="switchTab('logs')">Live-Logs</button>
                <button class="tab-btn" onclick="switchTab('geo')">Geo-Top</button>
                <button class="tab-btn" onclick="switchTab('bans')">Sperren</button>
                <button class="tab-btn" onclick="switchTab('whitelist')">Whitelist</button>
                <button class="tab-btn" onclick="switchTab('security')">Sicherheit</button>
                <button class="tab-btn" onclick="switchTab('status')">Status</button>
            </div>

            <!-- TAB 1: LOGS -->
            <div id="tab-logs" class="tab-content active">
                <div class="stats-grid">
                    <div class="stat-box"><div class="lbl">Aktuell (RPS)</div><div class="val" id="val-rps">0</div></div>
                    <div class="stat-box"><div class="lbl">Peak (Max)</div><div class="val" id="val-peak">0</div></div>
                    <div class="stat-box"><div class="lbl">Gesperrt</div><div class="val" id="val-banned-count">0</div></div>
                </div>
                <div class="log-box" id="log-container"></div>
                <div class="action-row">
                    <button class="btn" style="background:#1e293b;" onclick="clearLogs()">Logs leeren</button>
                    <button class="btn btn-danger" onclick="resetStats()">Zähler & Peak Reset</button>
                </div>
            </div>

            <!-- TAB 2: GEO -->
            <div id="tab-geo" class="tab-content">
                <p style="color:var(--text-muted); font-size:12px; margin-top:0;">Top Länder-Herkunft (Traffic Verteilung):</p>
                <div id="geo-list" style="max-height: 240px; overflow-y: auto;"></div>
            </div>

            <!-- TAB 3: SPERREN -->
            <div id="tab-bans" class="tab-content">
                <p style="color:var(--text-muted); font-size:12px; margin-top:0;">IP manuell permanent sperren:</p>
                <div style="display:flex; gap:8px;">
                    <input type="text" id="ban-ip-input" placeholder="z.B. 192.168.1.50">
                    <button class="btn btn-danger" style="width:120px;" onclick="manualBan()">Sperren</button>
                </div>
                <p style="color:var(--text-muted); font-size:12px;">Dauerhaft gesperrte IPs:</p>
                <div id="banned-list-container" style="max-height: 180px; overflow-y: auto;"></div>
            </div>

            <!-- TAB 4: WHITELIST -->
            <div id="tab-whitelist" class="tab-content">
                <p style="color:var(--text-muted); font-size:12px; margin-top:0;">IP zur Whitelist hinzufügen (Schutz vor Auto-Ban):</p>
                <div style="display:flex; gap:8px;">
                    <input type="text" id="whitelist-ip-input" placeholder="z.B. 192.168.1.100">
                    <button class="btn btn-success" style="width:120px;" onclick="manualWhitelist()">Erlauben</button>
                </div>
                <p style="color:var(--text-muted); font-size:12px;">Whitelisted IPs (von automatischen Sperren ausgenommen):</p>
                <div id="whitelist-list-container" style="max-height: 180px; overflow-y: auto;"></div>
            </div>

            <!-- TAB 5: SICHERHEIT -->
            <div id="tab-security" class="tab-content">
                <p style="color:var(--text-muted); font-size:12px; margin-top:0;">Wartungsmodus (Leitet normale Besucher ab):</p>
                <button id="btn-maint" class="btn btn-warning" onclick="toggleSetting('maintenance')">Wartung: AUS</button>
                <p style="color:var(--text-muted); font-size:12px; margin-top:15px;">Automatischer Bot-Schutz (IP Ratenbegrenzung & Auto-Ban):</p>
                <button id="btn-autoban" class="btn" onclick="toggleSetting('autoban')">Auto-Bot-Schutz: AN</button>
                <p style="color:var(--text-muted); font-size:12px; margin-top:15px;">Max. Anfragen pro IP innerhalb von 1 Sekunde:</p>
                <input type="number" id="input-max-req" onchange="updateConfigNum('max_ip_req', this.value)">
                <p style="color:var(--text-muted); font-size:12px; margin-top:5px;">Throttling-Verzögerung (Sekunden):</p>
                <input type="number" id="input-throttle" onchange="updateConfigNum('throttle_delay', this.value)">
                <p style="color:var(--text-muted); font-size:12px; margin-top:5px;">Globales Website-Limit (RPS Schwelle für 503):</p>
                <input type="number" id="input-limit" onchange="updateConfigNum('server_limit', this.value)">
            </div>

            <!-- TAB 6: STATUS -->
            <div id="tab-status" class="tab-content">
                <p style="color:var(--text-muted); font-size:12px; margin-top:0;">HTTP Status-Code Verteilung (Live-Zähler):</p>
                <div class="stats-grid">
                    <div class="stat-box"><div class="lbl">200 OK</div><div class="val" id="stat-200">0</div></div>
                    <div class="stat-box"><div class="lbl">403 Forbidden</div><div class="val" id="stat-403">0</div></div>
                    <div class="stat-box"><div class="lbl">503 Overloaded</div><div class="val" id="stat-503">0</div></div>
                </div>
                <div style="display:flex; gap:10px; margin-top:15px;">
                    <div class="stat-box" style="flex:1;"><div class="lbl">Server-Uhrzeit</div><div class="val" id="server-clock" style="font-size:14px;">00:00:00</div></div>
                    <div class="stat-box" style="flex:1;"><div class="lbl">Aktive IP-Tracker</div><div class="val" id="active-ips" style="font-size:14px;">0</div></div>
                </div>
            </div>

            <div style="margin-top: 20px;">
                <a href="/logout" class="btn btn-danger" style="background:#1e293b; color:white;">Abmelden</a>
            </div>
        </div>
    </div>

    <script>
        function switchTab(name) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + name).classList.add('active');
            event.target.classList.add('active');
        }

        function fetchData() {
            fetch('/api/stats').then(res => res.json()).then(data => {
                document.getElementById('val-rps').innerText = data.rps;
                document.getElementById('val-peak').innerText = data.peak_rps;
                document.getElementById('val-banned-count').innerText = data.banned_count;
                document.getElementById('uptime').innerText = "Uptime: " + data.uptime_str;
                document.getElementById('server-clock').innerText = data.server_time;
                document.getElementById('active-ips').innerText = data.active_ips;

                document.getElementById('stat-200').innerText = data.status_200;
                document.getElementById('stat-403').innerText = data.status_403;
                document.getElementById('stat-503').innerText = data.status_503;

                // Logs
                let logHtml = "";
                data.logs.forEach(l => {
                    logHtml += `<div class="log-item"><div><span style="color:#3b82f6;">${l.path}</span> <span style="color:#94a3b8;">${l.ua}</span><br><span style="color:#64748b; font-size:10px;">IP: ${l.ip} (${l.geo})</span></div><div style="color:#94a3b8; font-size:10px;">${l.time}</div></div>`;
                });
                document.getElementById('log-container').innerHTML = logHtml;

                // Geo Top
                let geoHtml = "";
                for (let [country, count] of Object.entries(data.geo_stats)) {
                    geoHtml += `<div class="list-item"><span>🌍 ${country}</span><span style="color:var(--primary);">${count} Aufrufe</span></div>`;
                }
                document.getElementById('geo-list').innerHTML = geoHtml || '<div style="color:#64748b;font-size:12px;text-align:center;padding:20px;">Noch keine Geo-Daten erfasst</div>';

                // Banned IPs
                let banHtml = "";
                data.banned_list.forEach(ip => {
                    banHtml += `<div class="list-item"><span>${ip}</span><button class="btn" style="padding:4px 8px; font-size:10px; width:auto;" onclick="removeBan('${ip}')">Freigeben</button></div>`;
                });
                document.getElementById('banned-list-container').innerHTML = banHtml || '<div style="color:#64748b;font-size:12px;text-align:center;padding:10px;">Keine gesperrten IPs</div>';

                // Whitelist IPs
                let wlHtml = "";
                data.whitelist_list.forEach(ip => {
                    wlHtml += `<div class="list-item"><span>${ip}</span><button class="btn btn-danger" style="padding:4px 8px; font-size:10px; width:auto;" onclick="removeWhitelist('${ip}')">Entfernen</button></div>`;
                });
                document.getElementById('whitelist-list-container').innerHTML = wlHtml;

                // Settings Buttons
                let btnM = document.getElementById('btn-maint');
                if(data.settings.maintenance) {
                    btnM.className = "btn btn-danger";
                    btnM.innerText = "Wartung: AN";
                } else {
                    btnM.className = "btn btn-warning";
                    btnM.innerText = "Wartung: AUS";
                }

                let btnA = document.getElementById('btn-autoban');
                if(data.settings.autoban) {
                    btnA.className = "btn";
                    btnA.innerText = "Auto-Bot-Schutz: AN";
                } else {
                    btnA.className = "btn";
                    btnA.style.background = "#475569";
                    btnA.innerText = "Auto-Bot-Schutz: AUS";
                }

                if(document.activeElement !== document.getElementById('input-max-req')) document.getElementById('input-max-req').value = data.settings.max_ip_req;
                if(document.activeElement !== document.getElementById('input-throttle')) document.getElementById('input-throttle').value = data.settings.throttle_delay;
                if(document.activeElement !== document.getElementById('input-limit')) document.getElementById('input-limit').value = data.settings.server_limit;
            });
        }

        function clearLogs() { fetch('/api/action?do=clear_logs').then(() => fetchData()); }
        function resetStats() { fetch('/api/action?do=reset_stats').then(() => fetchData()); }
        function manualBan() {
            let ip = document.getElementById('ban-ip-input').value;
            if(ip) { fetch('/api/action?do=ban&ip=' + ip).then(() => { document.getElementById('ban-ip-input').value = ''; fetchData(); }); }
        }
        function removeBan(ip) { fetch('/api/action?do=unban&ip=' + ip).then(() => fetchData()); }
        function manualWhitelist() {
            let ip = document.getElementById('whitelist-ip-input').value;
            if(ip) { fetch('/api/action?do=add_whitelist&ip=' + ip).then(() => { document.getElementById('whitelist-ip-input').value = ''; fetchData(); }); }
        }
        function removeWhitelist(ip) { fetch('/api/action?do=remove_whitelist&ip=' + ip).then(() => fetchData()); }
        function toggleSetting(name) { fetch('/api/action?do=toggle&name=' + name).then(() => fetchData()); }
        function updateConfigNum(name, val) { fetch('/api/action?do=set_num&name=' + name + '&val=' + val); }

        setInterval(fetchData, 1500);
        fetchData();
    </script>
</body>
</html>"""

LOGIN_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style>
        body { background: #090d16; color: white; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #131d31; border: 1px solid #1e293b; padding: 30px; border-radius: 16px; width: 300px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; }
        input { width: 100%; background: #070a12; border: 1px solid #1e293b; padding: 10px; border-radius: 8px; color: white; box-sizing: border-box; margin-bottom: 15px; }
        button { background: #3b82f6; color: white; border: none; padding: 10px; border-radius: 8px; width: 100%; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Admin Login</h2>
        <form method="POST" action="/admin">
            <input type="password" name="password" placeholder="Passwort eingeben" required>
            <button type="submit">Einloggen</button>
        </form>
    </div>
</body>
</html>"""

class TrafficHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global TOTAL_REQUESTS_COUNT, PEAK_RPS, MAINTENANCE_MODE, AUTO_BAN_ENABLED, MAX_REQUESTS_PER_IP, THROTTLE_DELAY, SERVER_LIMIT
        
        client_ip = self.client_address[0]
        now = time.time()
        
        TOTAL_REQUESTS_COUNT += 1
        REQUEST_TIMESTAMPS.append(now)
        
        while REQUEST_TIMESTAMPS and REQUEST_TIMESTAMPS[0] < now - WINDOW_SIZE:
            REQUEST_TIMESTAMPS.popleft()
        
        current_rps = len(REQUEST_TIMESTAMPS)
        if current_rps > PEAK_RPS:
            PEAK_RPS = current_rps

        if client_ip not in WHITELISTED_IPS:
            if client_ip in BANNED_IPS:
                status_code_stats[403] += 1
                self.send_error(403, "Access Denied")
                return
            
            ip_request_counts[client_ip] = [t for t in ip_request_counts[client_ip] if t > now - 1.0]
            ip_request_counts[client_ip].append(now)
            
            if AUTO_BAN_ENABLED and len(ip_request_counts[client_ip]) > MAX_REQUESTS_PER_IP:
                BANNED_IPS.add(client_ip)
                save_settings()
                status_code_stats[403] += 1
                self.send_error(403, "Auto-Banned due to high request rate")
                return

        if current_rps > SERVER_LIMIT:
            status_code_stats[503] += 1
            self.send_error(503, "Server Overloaded")
            return

        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        if path == "/admin":
            cookie = self.headers.get("Cookie", "")
            if "auth=true" in cookie:
                geo_loc, country = get_geoip_and_country(client_ip)
                country_stats[country] += 1
                status_code_stats[200] += 1
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(ADMIN_HTML.encode("utf-8"))
            else:
                status_code_stats[200] += 1
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(LOGIN_HTML.encode("utf-8"))
            return

        elif path == "/logout":
            status_code_stats[200] += 1
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.send_header("Set-Cookie", "auth=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/")
            self.end_headers()
            return

        elif path == "/api/stats":
            geo_loc, country = get_geoip_and_country(client_ip)
            uptime_sec = int(time.time() - START_TIME)
            uptime_str = f"{uptime_sec // 60}m {uptime_sec % 60}s"
            server_time = time.strftime("%H:%M:%S", time.localtime())

            data = {
                "rps": current_rps,
                "peak_rps": PEAK_RPS,
                "banned_count": len(BANNED_IPS),
                "uptime_str": uptime_str,
                "server_time": server_time,
                "active_ips": len(ip_request_counts),
                "status_200": status_code_stats[200],
                "status_403": status_code_stats[403],
                "status_503": status_code_stats[503],
                "logs": list(RECENT_LOGS),
                "geo_stats": dict(country_stats),
                "banned_list": list(BANNED_IPS),
                "whitelist_list": list(WHITELISTED_IPS),
                "settings": {
                    "maintenance": MAINTENANCE_MODE,
                    "autoban": AUTO_BAN_ENABLED,
                    "max_ip_req": MAX_REQUESTS_PER_IP,
                    "throttle_delay": THROTTLE_DELAY,
                    "server_limit": SERVER_LIMIT
                }
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        elif path == "/api/action":
            action = query.get("do", [""])[0]
            ip_param = query.get("ip", [""])[0]
            name_param = query.get("name", [""])[0]
            val_param = query.get("val", [""])[0]

            if action == "clear_logs":
                RECENT_LOGS.clear()
            elif action == "reset_stats":
                TOTAL_REQUESTS_COUNT = 0
                PEAK_RPS = 0
                country_stats.clear()
                status_code_stats.clear()
            elif action == "ban" and ip_param:
                BANNED_IPS.add(ip_param)
                save_settings()
            elif action == "unban" and ip_param:
                BANNED_IPS.discard(ip_param)
                save_settings()
            elif action == "add_whitelist" and ip_param:
                WHITELISTED_IPS.add(ip_param)
                save_settings()
            elif action == "remove_whitelist" and ip_param:
                WHITELISTED_IPS.discard(ip_param)
                save_settings()
            elif action == "toggle":
                if name_param == "maintenance":
                    MAINTENANCE_MODE = not MAINTENANCE_MODE
                elif name_param == "autoban":
                    AUTO_BAN_ENABLED = not AUTO_BAN_ENABLED
                save_settings()
            elif action == "set_num":
                try:
                    if name_param == "max_ip_req": MAX_REQUESTS_PER_IP = int(val_param)
                    elif name_param == "throttle_delay": THROTTLE_DELAY = float(val_param)
                    elif name_param == "server_limit": SERVER_LIMIT = int(val_param)
                    save_settings()
                except:
                    pass

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return

        geo_loc, country = get_geoip_and_country(client_ip)
        country_stats[country] += 1
        status_code_stats[200] += 1
        
        ua_string = self.headers.get("User-Agent", "Unknown")
        parsed_ua = parse_user_agent(ua_string)
        log_entry = {
            "path": path,
            "ua": parsed_ua,
            "ip": client_ip,
            "geo": geo_loc,
            "time": time.strftime("%H:%M:%S", time.localtime())
        }
        RECENT_LOGS.appendleft(log_entry)

        if MAINTENANCE_MODE:
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"<h1>Wartungsmodus aktiv</h1>")
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PUBLIC_HTML.encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        if self.path == "/admin":
            password = params.get("password", [""])[0]
            if password == ADMIN_PASSWORD:
                self.send_response(302)
                self.send_header("Location", "/admin")
                self.send_header("Set-Cookie", "auth=true; Path=/")
                self.end_headers()
                return
        
        self.send_response(302)
        self.send_header("Location", "/admin")
        self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), TrafficHandler) as httpd:
        print(f"Server läuft auf Port {PORT}")
        httpd.serve_forever()
