import json
import os

path = r"c:\Users\uid1937\Documents\AI_Project_Shuffle\shuffle_soc_factory\apps_full.json"
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

found = 0
for app_name, app_data in data.items():
    for key in app_data.keys():
        if ("image" in key.lower() or "icon" in key.lower()) and app_data[key]:
            print(f"--- {app_name} ---")
            print(f"  {key}: {str(app_data[key])[:50]}...")
            found += 1
            break
print(f"Total apps with image data found: {found}")
