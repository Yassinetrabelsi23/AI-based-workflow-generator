import requests, json, sys
sys.stdout.reconfigure(encoding='utf-8')
import config

H = {"Authorization": f"Bearer {config.SHUFFLE_API_KEY}"}
r = requests.get(f"{config.SHUFFLE_URL}/api/v1/apps", headers=H, verify=False, timeout=10)
apps = r.json()

# Look for Virustotal_v3
vt = next((a for a in apps if a.get('name') == 'Virustotal_v3'), None)
if vt:
    print(json.dumps(vt, indent=2))
else:
    print("Virustotal_v3 not found. Printing first app instead.")
    print(json.dumps(apps[0], indent=2))
