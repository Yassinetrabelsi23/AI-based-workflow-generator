"""Fetch the working SSH brute force workflow to study its real structure."""
import requests, json, sys
sys.stdout.reconfigure(encoding='utf-8')
import config

H = {"Authorization": f"Bearer {config.SHUFFLE_API_KEY}"}

r = requests.get(f"{config.SHUFFLE_URL}/api/v1/workflows", headers=H, verify=False, timeout=10)
workflows = r.json() if r.status_code == 200 else []

print(f"All workflows:")
for wf in workflows:
    n_actions = len(wf.get('actions', []))
    n_errors = len(wf.get('errors', []))
    valid = wf.get('is_valid', False)
    print(f"  [{('OK' if valid else 'ERR')}] {wf.get('name')} | actions={n_actions} | errors={n_errors} | id={wf.get('id')}")

# Find the working one (valid=True OR no errors)
working = None
for wf in workflows:
    if wf.get('is_valid') and len(wf.get('actions', [])) > 0:
        working = wf
        break

if not working:
    # Try one with fewest errors
    working = min(workflows, key=lambda w: len(w.get('errors', [])), default=None)

if working:
    wf_id = working['id']
    print(f"\nFetching: {working['name']} (id={wf_id})")
    r2 = requests.get(f"{config.SHUFFLE_URL}/api/v1/workflows/{wf_id}", headers=H, verify=False, timeout=10)
    if r2.status_code == 200:
        data = r2.json()
        with open("working_workflow.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("Saved to working_workflow.json")
        
        # Show action structure
        for i, action in enumerate(data.get('actions', [])[:3]):
            print(f"\n--- Action {i+1} ---")
            print(f"  name        : {action.get('name')}")
            print(f"  label       : {action.get('label')}")
            print(f"  app_name    : {action.get('app_name')}")
            print(f"  app_version : {action.get('app_version')}")
            print(f"  app_id      : {action.get('app_id')}")
            print(f"  action      : {action.get('action')}")
            print(f"  is_valid    : {action.get('is_valid')}")
