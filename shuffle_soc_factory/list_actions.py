import json
import os

catalog_path = r'c:\Users\uid1937\Documents\AI_Project_Shuffle\shuffle_soc_factory\apps_full.json'
if not os.path.exists(catalog_path):
    print(f"Catalog not found at {catalog_path}")
    exit(1)

with open(catalog_path, 'r') as f:
    data = json.load(f)

for app_name in ['TheHive', 'Virustotal_v3', 'Wazuh', 'Shuffle Tools']:
    print(f"\n--- {app_name} ---")
    app = data.get(app_name, {})
    if not app:
        print("App not found in catalog")
        continue
    
    actions = sorted(list(set(a['name'] for a in app.get('actions', []))))
    for action in actions:
        print(action)
