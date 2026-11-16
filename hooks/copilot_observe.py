import os, sys, urllib.request
raw = sys.stdin.read()
try:
    req = urllib.request.Request(os.environ.get("ACP_URL", "http://127.0.0.1:8787/hook"),
        data=raw.encode(), method="POST",
        headers={"Content-Type": "application/json", "X-ACP-Token": os.environ.get("ACP_TOKEN", "")})
    urllib.request.urlopen(req, timeout=5).read()
except Exception:
    pass
sys.stdout.write("{}")
