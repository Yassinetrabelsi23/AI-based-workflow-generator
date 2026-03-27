import json
import os
import re

# Paths
EXTRACTED_DATA_PATH = r'C:\Users\uid1937\Documents\AI_Project_Shuffle\extracted_app_data.json'
BRAIN_GENERATOR_PATH = r'C:\Users\uid1937\Documents\AI_Project_Shuffle\shuffle_soc_factory\brain_generator.py'

def update_brain():
    with open(EXTRACTED_DATA_PATH, 'r', encoding='utf-8') as f:
        extracted_data = json.load(f)

    with open(BRAIN_GENERATOR_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Update STATIC_CATALOG IDs
    id_mapping = {
        'Virustotal_v3': extracted_data.get('Virustotal v3', {}).get('id'),
        'TheHive': extracted_data.get('TheHive5', {}).get('id'),
        'Wazuh': extracted_data.get('Wazuh', {}).get('id')
    }

    for app_name, new_id in id_mapping.items():
        if not new_id: continue
        # Find the block for the app and replace the ID
        pattern = rf'"{app_name}": \{{[^}}]+?"id": "[^"]+"'
        def replacer(match):
            block = match.group(0)
            return re.sub(r'"id": "[^"]+"', f'"id": "{new_id}"', block)
        content = re.sub(pattern, replacer, content, flags=re.DOTALL)
    
    print("Updated IDs in STATIC_CATALOG.")

    # 2. Build and Insert LOGO_CATALOG
    logo_catalog = {
        "Virustotal_v3": extracted_data.get('Virustotal v3', {}).get('logo_full'),
        "TheHive": extracted_data.get('TheHive5', {}).get('logo_full'),
        "Wazuh": extracted_data.get('Wazuh', {}).get('logo_full')
    }
    
    logo_json = json.dumps(logo_catalog, indent=8)
    # Remove outer braces for insertion into class
    logo_body = logo_json.strip("{}").strip()
    
    logo_catalog_block = f"\n    LOGO_CATALOG = {{\n        {logo_body}\n    }}\n"
    
    if "LOGO_CATALOG =" not in content:
        # Insert after STATIC_CATALOG ends
        insertion_point = content.find('STATIC_CATALOG = {')
        # Find the closing brace of STATIC_CATALOG
        stack = 0
        found_start = False
        idx = insertion_point
        while idx < len(content):
            if content[idx] == '{':
                stack += 1
                found_start = True
            elif content[idx] == '}':
                stack -= 1
            if found_start and stack == 0:
                insertion_end = idx + 1
                break
            idx += 1
        else:
            raise ValueError("Could not find end of STATIC_CATALOG")
            
        content = content[:insertion_end] + logo_catalog_block + content[insertion_end:]
        print("Inserted LOGO_CATALOG.")
    else:
        print("LOGO_CATALOG already exists, skipping insertion.")

    # 3. Modify validate_and_fix to inject icons
    # Target lines:
    # fixed_workflow["actions"][i]["image"] = ""
    # fixed_workflow["actions"][i]["large_image"] = ""
    # fixed_workflow["actions"][i]["small_image"] = ""
    
    injection_code = """            app_logo = self.discovery.LOGO_CATALOG.get(matched_app_key, "")
            fixed_workflow["actions"][i]["image"] = app_logo
            fixed_workflow["actions"][i]["large_image"] = app_logo
            fixed_workflow["actions"][i]["small_image"] = app_logo"""
            
    old_block = r'fixed_workflow\["actions"\]\[i\]\["image"\] = ""\s+fixed_workflow\["actions"\]\[i\]\["large_image"\] = ""\s+fixed_workflow\["actions"\]\[i\]\["small_image"\] = ""'
    
    if 'fixed_workflow["actions"][i]["image"] = app_logo' not in content:
        content = re.sub(old_block, injection_code, content)
        print("Updated validate_and_fix icon injection.")
    else:
        print("validate_and_fix already updated.")

    with open(BRAIN_GENERATOR_PATH, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Success: brain_generator.py updated.")

if __name__ == "__main__":
    update_brain()
