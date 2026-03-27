#!/usr/bin/env python3
"""
deep_discover.py  — Shuffle App Deep Inspector
================================================
Queries YOUR live Shuffle instance and extracts:
  - Every installed app (name, id, app_version)
  - Every action in each app (exact name as stored in Shuffle)
  - Every parameter for each action

Outputs:
  1. Console table (human-readable summary)
  2. apps_full.json  — complete machine-readable catalog
  3. apps_catalog.py — ready-to-paste STATIC_CATALOG block for brain_generator.py

Run: python deep_discover.py
"""

import sys
import json
import requests

sys.stdout.reconfigure(encoding="utf-8")

# ── Config (reads directly from .env via config.py) ──────────────────────────
import config

HEADERS = {
    "Authorization": f"Bearer {config.SHUFFLE_API_KEY}",
    "Content-Type": "application/json",
}

VERIFY = config.SSL_VERIFY


# ── Helpers ───────────────────────────────────────────────────────────────────

def api_get(path: str, timeout: int = 20) -> tuple[int, object]:
    """GET from Shuffle API, return (status_code, json_data)."""
    url = f"{config.SHUFFLE_URL}{path}"
    try:
        r = requests.get(url, headers=HEADERS, verify=VERIFY, timeout=timeout)
        try:
            data = r.json()
        except Exception:
            data = r.text
        return r.status_code, data
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Cannot connect to {url}")
        return 0, {}
    except requests.exceptions.Timeout:
        print(f"  [ERROR] Timeout on {url}")
        return 0, {}


def extract_actions(app_data: dict) -> list[dict]:
    """
    Extract action list from an app dict.
    Returns list of {"name": str, "description": str, "parameters": [...]}.
    """
    raw = app_data.get("actions", [])
    actions = []
    for a in raw:
        if isinstance(a, dict):
            params = []
            for p in (a.get("parameters") or []):
                if isinstance(p, dict):
                    params.append({
                        "name": p.get("name", ""),
                        "required": p.get("required", False),
                        "example": p.get("example", ""),
                    })
                elif isinstance(p, str):
                    params.append({"name": p, "required": False, "example": ""})
            actions.append({
                "name": a.get("name", ""),
                "description": a.get("description", ""),
                "parameters": params,
            })
        elif isinstance(a, str):
            actions.append({"name": a, "description": "", "parameters": []})
    return actions


# ── 1. Fetch all apps ─────────────────────────────────────────────────────────

print("=" * 70)
print("SHUFFLE APP DEEP INSPECTOR")
print(f"Instance: {config.SHUFFLE_URL}")
print("=" * 70)

print("\n[1/3] Fetching all apps from /api/v1/apps ...")
status, apps_raw = api_get("/api/v1/apps")
print(f"      HTTP {status}")

if status != 200 or not isinstance(apps_raw, list):
    print(f"\n[FATAL] Could not fetch apps (HTTP {status}).")
    print(f"  Response: {str(apps_raw)[:300]}")
    sys.exit(1)

print(f"      Found {len(apps_raw)} apps total")

# ── 2. Also hit /api/v1/apps?field=active to get only active apps ─────────────
print("\n[2/3] Trying /api/v1/apps?field=active ...")
status2, apps_active = api_get("/api/v1/apps?field=active")
if status2 == 200 and isinstance(apps_active, list) and apps_active:
    print(f"      Found {len(apps_active)} active apps")
    apps_source = apps_active
    source_label = "active"
else:
    print(f"      Not available (HTTP {status2}), using full list")
    apps_source = apps_raw
    source_label = "all"

# ── 3. Deep inspection of each app ───────────────────────────────────────────

print(f"\n[3/3] Deep inspecting {len(apps_source)} apps ({source_label}) ...")

full_catalog = {}   # name -> full data
simple_catalog = {} # name -> {id, version, actions: [str, ...]}

for app in apps_source:
    name    = app.get("name", "")
    app_id  = app.get("id", "")
    version = app.get("app_version", app.get("version", "?"))
    
    # Try to get actions from the list response first
    actions = extract_actions(app)
    
    # If no actions, try detail endpoint
    if not actions and app_id:
        det_status, det_data = api_get(f"/api/v1/apps/{app_id}")
        if det_status == 200 and isinstance(det_data, dict):
            actions = extract_actions(det_data)

    full_catalog[name] = {
        "id": app_id,
        "version": version,
        "actions": actions,
    }
    simple_catalog[name] = {
        "id": app_id,
        "version": version,
        "actions": [a["name"] for a in actions],
    }

# ── 4. Print human-readable summary ──────────────────────────────────────────

print("\n" + "=" * 70)
print("INSTALLED APPS SUMMARY")
print("=" * 70)

SOC_KEYWORDS = ["virustotal", "wazuh", "thehive", "http", "shuffle", "misp", "cortex"]

highlighted = []
others = []
for name, data in simple_catalog.items():
    if any(k in name.lower() for k in SOC_KEYWORDS):
        highlighted.append((name, data))
    else:
        others.append((name, data))

print(f"\n{'SOC-relevant apps':}")
print("-" * 70)
for name, data in sorted(highlighted, key=lambda x: x[0]):
    print(f"\nAPP: {name}")
    print(f"  id:      {data['id']}")
    print(f"  version: {data['version']}")
    print(f"  actions ({len(data['actions'])}):")
    for a in data["actions"]:
        print(f"    - \"{a}\"")

print(f"\n{'Other apps ({} total):'.format(len(others))}")
print("-" * 70)
for name, data in sorted(others, key=lambda x: x[0]):
    action_preview = ", ".join(data["actions"][:5])
    if len(data["actions"]) > 5:
        action_preview += f" ... (+{len(data['actions'])-5} more)"
    print(f"  {name:40s} v{data['version']:10s} | {len(data['actions'])} actions | {action_preview}")

# ── 5. Save apps_full.json ────────────────────────────────────────────────────

full_path = "apps_full.json"
with open(full_path, "w", encoding="utf-8") as f:
    json.dump(full_catalog, f, indent=2, ensure_ascii=False)
print(f"\n[OK] Saved complete catalog to: {full_path}")

simple_path = "apps_discovered.json"
with open(simple_path, "w", encoding="utf-8") as f:
    json.dump(simple_catalog, f, indent=2, ensure_ascii=False)
print(f"[OK] Updated: {simple_path}")

# ── 6. Generate ready-to-paste STATIC_CATALOG Python block ───────────────────

catalog_path = "apps_catalog.py"
with open(catalog_path, "w", encoding="utf-8") as f:
    f.write("# AUTO-GENERATED by deep_discover.py\n")
    f.write("# Paste this as STATIC_CATALOG in brain_generator.py ShuffleAppDiscovery\n\n")
    f.write("STATIC_CATALOG = {\n")
    for name, data in simple_catalog.items():
        f.write(f'    "{name}": {{\n')
        f.write(f'        "id": "{data["id"]}",\n')
        f.write(f'        "version": "{data["version"]}",\n')
        f.write(f'        "actions": [\n')
        for a in data["actions"]:
            f.write(f'            "{a}",\n')
        f.write(f'        ],\n')
        f.write(f'    }},\n')
    f.write("}\n")

print(f"[OK] Generated Python catalog: {catalog_path}")

# ── 7. Print VirusTotal + http action details explicitly ─────────────────────

print("\n" + "=" * 70)
print("EXACT ACTION NAMES FOR KEY APPS (COPY THESE INTO brain_generator.py)")
print("=" * 70)

for target in ["Virustotal_v3", "Virustotal_v30", "virustotal", "http", "Wazuh"]:
    found = [(n, d) for n, d in simple_catalog.items() if target.lower() in n.lower()]
    for name, data in found:
        print(f"\n  App: \"{name}\"")
        print(f"  id:      {data['id']}")
        print(f"  version: {data['version']}")
        print(f"  actions:")
        for a in data["actions"]:
            print(f"    \"{a}\"")

print("\n" + "=" * 70)
print("DONE — Share apps_full.json and the output above to update brain_generator.py")
print("=" * 70)
