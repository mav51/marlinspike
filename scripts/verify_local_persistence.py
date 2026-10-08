"""Read-only verification of the sample report after an application restart."""
import http.cookiejar
import json
import urllib.parse
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
env = dict(line.split("=", 1) for line in (root / ".env").read_text().splitlines()
           if line and not line.startswith("#") and "=" in line)
result = json.loads((root / ".smoke/verification-result.json").read_text())
base = "http://127.0.0.1:5001"
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
login = urllib.parse.urlencode({"username": "admin", "password": env["ADMIN_PASSWORD"]}).encode()
with client.open(base + "/login", login, timeout=30) as response:
    assert response.status == 200 and response.url != base + "/login"
with client.open(result["viewer_url"], timeout=30) as response:
    assert response.status == 200 and response.url == result["viewer_url"]
with client.open(base + f'/api/reports/{result["report"]}?project_id={result["project_id"]}', timeout=30) as response:
    report = json.load(response)
    assert len(report["nodes"]) == result["nodes"]
    assert len(report["extensions"]) >= 4
print("PASS: administrator credentials, project report, topology, and enrichment persisted after restart")
