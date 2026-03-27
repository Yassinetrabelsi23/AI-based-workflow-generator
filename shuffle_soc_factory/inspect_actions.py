import requests, json, sys
sys.stdout.reconfigure(encoding='utf-8')
import config

H = {"Authorization": f"Bearer {config.SHUFFLE_API_KEY}"}
r = requests.get(f"{config.SHUFFLE_URL}/api/v1/apps", headers=H, verify=False, timeout=10)
apps = r.json()

vt = next((a for a in apps if a.get('name') == 'Virustotal_v3'), None)
if vt:
    actions = vt.get('actions', [])
    for a in actions[:10]:
        print(f"Action: {a.get('name')} | ID: {a.get('id')}")
else:
    print("Virustotal_v3 not found.")
