
import json
import os

files = [
    r"c:\Users\uid1937\Documents\AI_Project_Shuffle\apps\TheHive5 (1).json",
    r"c:\Users\uid1937\Documents\AI_Project_Shuffle\apps\Virustotal v3 (1).json",
    r"c:\Users\uid1937\Documents\AI_Project_Shuffle\apps\Wazuh.json"
]

results = {}

for fpath in files:
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
            info = data.get("info", {})
            logo = info.get("x-logo", "")
            app_id = data.get("id", "NOT_FOUND")
            title = info.get("title", os.path.basename(fpath))
            results[title] = {
                "id": app_id,
                "logo_preview": logo[:50] + "...",
                "logo_full": logo
            }
            print(f"File: {os.path.basename(fpath)}")
            print(f"  Title: {title}")
            print(f"  ID: {app_id}")
            print(f"  Logo Length: {len(logo)}")
    except Exception as e:
        print(f"Error processing {fpath}: {e}")

# Print results directly for easy viewing
for title, info in results.items():
    print("---")
    print(f"App: {title}")
    print(f"ID: {info['id']}")
    print(f"Logo (first 100 chars): {info['logo_full'][:100]}")
    print(f"Logo Length: {len(info['logo_full'])}")

# Save to current directory
with open("extracted_app_data.json", "w") as out:
    json.dump(results, out, indent=2)
