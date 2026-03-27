"""Explore apps Shuffle - ASCII safe output."""
import requests, json, sys
import config

sys.stdout.reconfigure(encoding='utf-8')

H = {"Authorization": f"Bearer {config.SHUFFLE_API_KEY}"}

def get(path, timeout=15):
    r = requests.get(f"{config.SHUFFLE_URL}{path}", headers=H, verify=False, timeout=timeout)
    try:
        data = r.json()
    except Exception:
        data = {}
    return r.status_code, data

# 1. Get all apps
status, apps = get("/api/v1/apps")
print(f"/api/v1/apps status={status} count={len(apps) if isinstance(apps, list) else 'N/A'}")

if not isinstance(apps, list) or not apps:
    print("No apps returned")
    sys.exit(1)

# Show first app structure
print("\n=== FIRST APP STRUCTURE ===")
print(json.dumps(apps[0], indent=2, ensure_ascii=True)[:3000])

# Filter SOC relevant apps
TARGETS = ["virustotal", "thehive", "wazuh", "http", "shuffle", "misp", "cortex"]
soc_apps = [a for a in apps if any(t in a.get("name","").lower() for t in TARGETS)]
print(f"\n=== SOC APPS FOUND: {len(soc_apps)} ===")

results = {}
for app in soc_apps:
    name = app.get("name", "")
    app_id = app.get("id", "")
    version = app.get("app_version", "")
    print(f"\nAPP: {name} | ID: {app_id} | v{version}")

    # Try different action endpoints
    actions = app.get("actions", [])
    if actions:
        print(f"  Actions from list ({len(actions)}):")
        for a in actions[:20]:
            aname = a.get("name","") if isinstance(a, dict) else str(a)
            print(f"    - {aname}")
        results[name] = {"id": app_id, "version": version, "actions": [a.get("name","") if isinstance(a,dict) else a for a in actions[:20]]}
    else:
        # Try detail endpoint
        s2, d2 = get(f"/api/v1/apps/{app_id}")
        actions2 = d2.get("actions", [])
        print(f"  Detail endpoint status={s2} actions={len(actions2)}")
        if actions2:
            for a in actions2[:20]:
                print(f"    - {a.get('name','')}")
            results[name] = {"id": app_id, "version": version, "actions": [a.get("name","") for a in actions2[:20]]}
        else:
            print("  No actions found")
            results[name] = {"id": app_id, "version": version, "actions": []}

# Save results
with open("apps_discovered.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=True)
print("\n\nSaved to apps_discovered.json")
