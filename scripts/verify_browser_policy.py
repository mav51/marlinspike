"""Verify the deployed header authorizes the controls rendered by the app."""
import http.cookiejar
from html.parser import HTMLParser
from pathlib import Path
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parents[1]
env = dict(line.split("=", 1) for line in (root / ".env").read_text().splitlines()
           if line and not line.startswith("#") and "=" in line)
base = "http://127.0.0.1:5001"
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
login = urllib.parse.urlencode({"username": "admin", "password": env["ADMIN_PASSWORD"]}).encode()
with client.open(base + "/login", login, timeout=30) as response:
    assert response.url.endswith("/dashboard"), "Login failed"


class Controls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.handlers = []
        self.nonces = []
        self.styles = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.handlers.extend(value for key, value in attrs.items() if key.startswith("on"))
        self.styles += "style" in attrs
        if tag in ("script", "style") and "src" not in attrs:
            self.nonces.append((tag, attrs.get("nonce")))


for path, create_handler, upload_handler in (
    ("/dashboard", "MS.createNewProject", "upload-input"),
    ("/projects", "PROJ.createProject", "proj-upload-input"),
):
    with client.open(base + path, timeout=30) as response:
        html = response.read().decode()
        policy = {parts[0]: parts[1:] for chunk in response.headers["Content-Security-Policy"].split(";")
                  if (parts := chunk.strip().split())}
    controls = Controls()
    controls.feed(html)
    assert any(create_handler in handler for handler in controls.handlers)
    assert any(upload_handler in handler for handler in controls.handlers)
    assert controls.styles
    for kind in ("script", "style"):
        assert policy[kind + "-src-attr"] == ["'unsafe-inline'"]
        assert "'unsafe-inline'" not in policy[kind + "-src"]
    for tag, nonce in controls.nonces:
        assert nonce and f"'nonce-{nonce}'" in policy[tag + "-src"]
    print(f"PASS: {path}: create/upload handlers and inline styles permitted; all script/style elements have matching nonces")
