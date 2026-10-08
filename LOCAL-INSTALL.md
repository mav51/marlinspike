# Local MarlinSpike Installation

## Access

- URL: http://127.0.0.1:5001
- Username: `admin`
- Password: the `ADMIN_PASSWORD` value in the local `.env` file.
- Source: https://github.com/eris-ot/marlinspike, commit `853bc3c`, package version `3.6.0`.

The `.env` file contains independently generated application, database, and admin secrets. It is excluded from Git and readable only by your account (mode `0600`). This deployment uses local HTTP with `SESSION_COOKIE_SECURE=false`; only localhost port 5001 is published.

## Services and Dependencies

Docker Compose runs the application, PostgreSQL 16, and Redis 7. The app image includes Python 3.12, tshark 4.4.19, Rust DPI 1.7.0, the malware IOC engine and rule packs, and the MITRE, ARP, APT, and CISA plugins. Host-side Python packages or tshark are unnecessary.

Docker is enabled at boot, and the services use `restart: unless-stopped`. The local operator account was added to the Docker group. Existing terminals may need `newgrp docker` or a fresh login before Docker commands work.

Live capture is optional and remains disabled. This installation analyzes uploaded PCAP files; no network capture or active probing was performed.

## Management

Run commands from the repository root:

```bash
docker compose ps                     # service health
docker compose logs --tail=100 app    # recent application logs
docker compose stop                  # stop without removing data
docker compose up -d --wait           # start and wait for health checks
docker compose restart app           # restart the application
docker compose up -d --build --wait   # rebuild after code changes
```

Uploads and reports persist in the Compose data volume; accounts and projects persist in the PostgreSQL volume. Avoid `docker compose down -v` unless you intend to delete those volumes. Back up both volumes before upgrades.

## Local Compatibility Fixes

The checked-out source includes these installation fixes:

- Install `protobuf-compiler` in the Rust DPI build stage.
- Select the installed PostgreSQL driver explicitly with `postgresql+psycopg2`.
- Replace an obsolete engine import on the capabilities page.
- Set `MARLINSPIKE_PROJECT_ROOT=/app` so engine subprocesses find enrichment rules.
- Resolve the IEEE OUI database from that project root.
- Add an HTTP health check for the application.
- Separate CSP permissions for legacy event/style attributes from nonced script/style elements. Without `script-src-attr` and `style-src-attr`, modern browsers block the existing buttons and inline layout styles. Attribute-level inline execution remains allowed for compatibility until those handlers are migrated to event listeners.

Keep these changes when upgrading until upstream incorporates equivalent fixes. Regression tests cover the capabilities catalog and vendor asset path.

## Verification

The isolated Python 3.12 test run passed **369 tests**; 87 non-fatal warnings were reported. `pip check` found no broken requirements.

The HTTP workflow verified admin login, main pages, project creation, synthetic Modbus PCAP upload, Rust analysis, two-host topology, report viewing, aggregation, and exports. All four enrichment plugins completed, and 38,926 IEEE vendor entries loaded. OCSF and STIX downloads succeeded; Navigator and Sigma correctly returned no applicable results for this sample. After an application restart, all services were healthy and the saved credentials, report, topology, and enrichment remained accessible.

Local verification output is stored in the Git-ignored `.smoke/` directory, including `tests-final.log`, `workflow.log`, `scan-output.json`, and `verification-result.json`. Sample verification projects remain available in the app. Browser rendering was not visually checked because no browser automation connection was available.

The browser-control fix has additional evidence in `csp-tests.log` and `browser-policy-before.log`. Run `python3 scripts/verify_browser_policy.py` to check the deployed Dashboard and Projects markup against their actual CSP headers. Reload open pages after deployment to receive the corrected policy.

## Repeat the Local Verification

After configuring `.env` and starting the local stack, run:

```bash
python3 scripts/verify_browser_policy.py
python3 scripts/verify_local_install.py
docker compose restart app
docker compose up -d --wait
python3 scripts/verify_local_persistence.py
```

These scripts read the administrator password from `.env` without printing it. The installation check creates a labeled test project and a synthetic 40-packet Modbus capture, then writes its results to `.smoke/`. The persistence check reads the most recent verification result. The policy check examines served markup and HTTP headers; it does not replace an interactive browser test.
