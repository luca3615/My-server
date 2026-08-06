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
    "max_ip_req": 5,
    "server_limit": 450,
    "throttle_delay": 2.0,
    "banned_ips": ["103.43.191.71", "175.6.75.144"],
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
        body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 15px; display: flex; flex-direction: column; align-items: center; min-height: 100vh; box-sizing: border-box; }
        .container { width: 100%; max-width: 500px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); padding: 20px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); margin-bottom: 20px; }
        .header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; font-size: 15px; font-weight: bold; }
        .badge-aktiv { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: var(--success); padding: 3px 10px; border-radius: 20px; font-size: 11px; }
        .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }
        .stat-box { background: #0f172a; border: 1px solid var(--border); padding: 12px; border-radius: 10px; text-align: center; }
        .stat-box .val { font-size: 20px; font-weight: bold; color: var(--primary); margin-top: 5px; }
        .stat-box .lbl { font-size: 11px; color: var(--text-muted); }
        .chart-container { background: #070a12; border: 1px solid var(--border); border-radius: 12px; padding: 15px; height: 160px; display: flex; align-items: flex-end; justify-content: space-between; gap: 4px; box-sizing: border-box; margin-bottom: 15px; }
        .bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; }
        .bar { width: 100%; background: linear-gradient(to top, var(--primary), var(--accent)); border-radius: 4px 4px 0 0; transition: height 0.3s ease; min-height: 3px; }
        .chart-title { font-size: 12px; color: var(--text-muted); margin-bottom: 8px; display: flex; justify-content: space-between; }
        .log-box { background: #070a12; border: 1px solid var(--border); border-radius: 8px; padding: 10px; height: 140px; overflow-y: auto; font-family: monospace; font-size: 11px; }
        .log-item { padding: 5px 0; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header-row">
                <span>Live Traffic Monitor</span>
                <span class="badge-aktiv">● Live</span>
            </div>
            <div class="stats-grid">
                <div class="stat-box"><div class="lbl">Aktuell (RPS)</div><div class="val" id="val-rps">0</div></div>
                <div class="stat-box"><div class="lbl">Peak (Max RPS)</div><div class="val" id="val-peak">0</div></div>
            </div>
            <div class="chart-title">
                <span>Live RPS Verlauf</span>
                <span id="uptime" style="font-size:11px;">Uptime: 0m 0s</span>
            </div>
            <div class="chart-container" id="chart-bars"></div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">Letzte Anfragen:</div>
            <div class="log-box" id="log-container"></div>
        </div>
    </div>
    <script>
        let rpsHistory = new Array(15).fill(0);
        function fetchData() {
            fetch('/api/stats').then(res => res.json()).then(data => {
                document.getElementById('val-rps').innerText = data.rps;
                document.getElementById('val-peak').innerText = data.peak_rps;
                document.getElementById('uptime').innerText = "Uptime: " + data.uptime_str;
                rpsHistory.shift();
                rpsHistory.push(data.rps);
                let maxVal = Math.max(...rpsHistory, 5);
                let chartHtml = "";
                let heightPx = 110;
                rpsHistory.forEach(val => {
                    let barHeight = Math.max(4, Math.round((val / maxVal) * heightPx));
                    chartHtml += `<div class="bar-col"><div style="font-size:9px; color:#94a3b8; margin-bottom:3px;">${val > 0 ? val : ''}</div><div class="bar" style="height: ${barHeight}px;"></div></div>`;
                });
                document.getElementById('chart-bars').innerHTML = chartHtml;
                let logHtml = "";
                data.logs.forEach(l => {
                    logHtml += `<div class="log-item"><div><span style="color:#3b82f6;">${l.path}</span> <span style="color:#94a3b8;">${l.ua}</span></div><div style="color:#64748b; font-size:10px;">${l.time}</div></div>`;
                });
                document.getElementById('log-container').innerHTML = logHtml;
            });
        }
        setInterval(fetchData, 1000);
        fetchData();
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
        body { background: #000000; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
        .box { background: #0b0f19; border: 1px solid #1e293b; padding: 40px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.9); max-width: 400px; width: 90%; }
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
        <p>Das System wird aktuell gewartet. Wir sind in Kürze wieder für dich da!</p>
    </div>
</body>
</html>"""

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8"><title>Admin Login</title>
    <style>
        body { background: #05070b; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .box { background: #131d31; padding: 30px; border-radius: 12px; border: 1px solid #1e293b; width: 300px; text-align: center; }
        input { width: 90%; padding: 10px; margin: 10px 0; background: #090d16; border: 1px solid #1e293b; color: #fff; border-radius: 6px; }
        button { width: 100%; padding: 10px; background: #3b82f6; border: none; color: #fff; border-radius: 6px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="box">
        <h3>Admin Login</h3>
        <form method="POST" action="/admin/login">
            <input type="password" name="password" placeholder="Passwort eingeben" required>
            <button type="submit">Einloggen</button>
        </form>
    </div>
</body>
</html>"""

ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8"><title>Admin Panel</title>
    <style>
        body { background: #05070b; color: #f1f5f9; font-family: sans-serif; padding: 20px; }
        .container { max-width: 800px; margin: auto; }
        .card { background: #131d31; border: 1px solid #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: monospace; }
        th, td { padding: 8px; border-bottom: 1px solid #1e293b; text-align: left; }
        button { background: #3b82f6; border: none; color: #fff; padding: 6px 12px; border-radius: 4px; cursor: pointer; }
        .btn-danger { background: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Admin Bedienpanel</h2>
        <div class="card">
            <h3>Steuerung</h3>
            <form action="/admin/toggle-maintenance" method="POST" style="display:inline;">
                <button type="submit">Wartungsmodus umschalten</button>
            </form>
        </div>
        <div class="card">
            <h3>Echte Live-Anfragen (Mit echten IPs)</h3>
            <table>
                <tr><th>Zeit</th><th>IP-Adresse</th><th>Pfad</th><th>Browser/Gerät</th></tr>
                __LOGS_TABLE__
            </table>
        </div>
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

        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/admin":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                logs_html = ""
                for l in RECENT_LOGS:
                    logs_html += f"<tr><td>{l['time']}</td><td>{l['real_ip']}</td><td>{l['path']}</td><td>{l['ua']}</td></tr>"
                page = ADMIN_PANEL_HTML.replace("__LOGS_TABLE__", logs_html)
                self.wfile.write(page.encode("utf-8"))
                return
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(ADMIN_LOGIN_HTML.encode("utf-8"))
                return

        if MAINTENANCE_MODE:
            self.send_response(503)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(MAINTENANCE_HTML.encode("utf-8"))
            return

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

        if path == "/api/stats":
            uptime_sec = int(time.time() - START_TIME)
            uptime_str = f"{uptime_sec // 60}m {uptime_sec % 60}s"

            # Öffentliche Logs zeigen anonymisierte IPs
            public_logs = []
            for l in RECENT_LOGS:
                public_logs.append({
                    "path": l["path"],
                    "ua": l["ua"],
                    "time": l["time"]
                })

            data = {
                "rps": current_rps,
                "peak_rps": PEAK_RPS,
                "uptime_str": uptime_str,
                "logs": public_logs
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        geo_loc, country = get_geoip_and_country(client_ip)
        country_stats[country] += 1
        status_code_stats[200] += 1
        
        ua_string = self.headers.get("User-Agent", "Unknown")
        parsed_ua = parse_user_agent(ua_string)
        
        # Log speichert intern die echte IP für das Admin-Panel
        log_entry = {
            "path": path,
            "ua": parsed_ua,
            "real_ip": client_ip, 
            "time": time.strftime("%H:%M:%S", time.localtime())
        }
        RECENT_LOGS.appendleft(log_entry)

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PUBLIC_HTML.encode("utf-8"))

    def do_POST(self):
        global MAINTENANCE_MODE
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
                self.send_header('Location', '/admin')
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Falsches Passwort!")
            return

        if path == "/admin/toggle-maintenance":
            cookie = self.headers.get("Cookie", "")
            if f"session={ADMIN_PASSWORD}" in cookie:
                MAINTENANCE_MODE = not MAINTENANCE_MODE
                save_settings()
                self.send_response(303)
                self.send_header('Location', '/admin')
                self.end_headers()
                return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), TrafficHandler) as httpd:
        print(f"Server läuft auf Port {PORT}")
        httpd.serve_forever()

