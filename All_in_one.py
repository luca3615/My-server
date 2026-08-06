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
