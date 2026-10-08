"""Exercise the local deployment with synthetic traffic; sends no network probes."""
import http.cookiejar
import json
import re
import socket
import struct
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
(ROOT / ".smoke").mkdir(exist_ok=True)
BASE = "http://127.0.0.1:5001"
env = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
           if line and not line.startswith("#") and "=" in line)
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""


def request(path, data=None, content_type=None):
    headers = {"Origin": BASE}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    with client.open(req, timeout=30) as response:
        assert response.status == 200
        return response.read()


def api(path, data=None):
    return json.loads(request(path, json.dumps(data).encode() if data is not None else None,
                              "application/json" if data is not None else None))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(response, index):
    src, dst = ("192.168.50.10", "192.168.50.20")
    smac, dmac = bytes.fromhex("001122334455"), bytes.fromhex("001122334466")
    sport, dport = 40000, 502
    payload = struct.pack("!HHHBBHH", index, 0, 6, 1, 3, 0, 1)
    if response:
        src, dst, smac, dmac, sport, dport = dst, src, dmac, smac, dport, sport
        payload = struct.pack("!HHHBBB H", index, 0, 5, 1, 3, 2, 42)
    src, dst = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, index * 12, 1, 0x50, 0x18, 8192, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), index, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return dmac + smac + b"\x08\x00" + ip + tcp + payload


login = urllib.parse.urlencode({"username": "admin", "password": env["ADMIN_PASSWORD"]}).encode()
html = request("/login", login, "application/x-www-form-urlencoded").decode()
assert 'name="csrf-token"' in html, "Login did not reach dashboard"
csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
print("PASS: administrator login", flush=True)
for path in ("/projects", "/reports", "/capabilities", "/system", "/api/admin/stats"):
    request(path)
print("PASS: main pages and admin statistics", flush=True)
project = api("/api/projects", {"name": "Installation verification " + str(int(time.time()))})
pid = project["id"]
pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
for i in range(1, 21):
    for response in (False, True):
        frame = packet(response, i)
        pcap += struct.pack("<IIII", 1700000000 + i, 1000 if response else 0, len(frame), len(frame)) + frame
(ROOT / ".smoke" / "verification.pcap").write_bytes(pcap)
boundary = "MarlinSpikeInstallVerification"
body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="verification.pcap"\r\n'
        'Content-Type: application/vnd.tcpdump.pcap\r\n\r\n').encode() + pcap + f"\r\n--{boundary}--\r\n".encode()
uploaded = json.loads(request(f"/api/projects/{pid}/upload", body, f"multipart/form-data; boundary={boundary}"))
assert uploaded["ok"], uploaded
print("PASS: project creation and synthetic Modbus PCAP upload", flush=True)
run = api("/api/scans/start", {"project_id": pid, "pcap_file": "verification.pcap", "command": "chain"})
rid = run["run_id"]
for _ in range(120):
    status = api(f"/api/runs/{rid}/status")
    if status["status"] != "running":
        break
    time.sleep(2)
print(json.dumps(status, indent=2), flush=True)
assert status["status"] == "completed", api(f"/api/runs/{rid}/output")
(ROOT / ".smoke" / "scan-output.json").write_text(json.dumps(api(f"/api/runs/{rid}/output"), indent=2))
filename = status["report_filename"]
report_path = f"/api/reports/{filename}"
report = api(report_path + f"?project_id={pid}")
(ROOT / ".smoke" / "verification-report.json").write_text(json.dumps(report, indent=2))
assert len(report.get("nodes", [])) >= 2, "Expected two synthetic hosts"
assert report.get("edges"), "Expected a communication edge"
assert {"marlinspike-mitre", "marlinspike-arp", "marlinspike-apt", "marlinspike-cisa"} <= set(report.get("extensions", {}))
assert report.get("dpi_engine") == "marlinspike-dpi", report.get("dpi_engine")
request(report_path + f"/viewer?project_id={pid}")
aggregate = api(f"/api/projects/{pid}/aggregate")
for fmt in ("ocsf", "navigator", "stix", "sigma"):
    try:
        request(report_path + f"/{fmt}?project_id={pid}")
        print(f"PASS: {fmt} export", flush=True)
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read())
        expected = {"navigator": "No ics-attack techniques in report",
                    "sigma": "No Sigma-emittable findings in report"}
        assert error.code == 404 and payload.get("error") == expected.get(fmt), payload
        print(f"PASS: {fmt} correctly reports no applicable findings", flush=True)
result = {"project_id": pid, "run_id": rid, "report": filename,
          "nodes": len(report["nodes"]), "edges": len(report["edges"]),
          "viewer_url": BASE + report_path + f"/viewer?project_id={pid}"}
(ROOT / ".smoke" / "verification-result.json").write_text(json.dumps(result, indent=2))
print("PASS: analysis, topology, report viewer, aggregate, and export endpoints", flush=True)
print(json.dumps(result, indent=2))
