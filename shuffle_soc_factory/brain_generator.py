#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          SHUFFLE SOC FACTORY — brain_generator.py  v4.0                     ║
║                                                                              ║
║  FIX: Strict Action Name Mapping & Label-based Variable Referencing         ║
║  Architecture :                                                              ║
║    1. ShuffleAppDiscovery   — Fetches EXACT internal action IDs from host   ║
║    2. CyberContextInjector  — Enriches prompt with SOC stack context        ║
║    3. OpenAIWorkflowEngine  — GPT-4 generates JSON using internal names      ║
║    4. ShuffleImporter       — POSTs the workflow to the local instance      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import json
import base64
import re
from typing import Optional, Dict, List

import requests
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

import config

console = Console()

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — Shuffle App Discovery (Fetches exact internal names)
# ══════════════════════════════════════════════════════════════════════════════

class ShuffleAppDiscovery:
    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {config.SHUFFLE_API_KEY}",
            "Content-Type": "application/json",
        }
        self._catalog: Dict = {}

    def load(self) -> Dict:
        """Fetches apps and their actions directly from the Shuffle API."""
        try:
            resp = requests.get(
                f"{config.SHUFFLE_URL}/api/v1/apps",
                headers=self.headers,
                verify=config.SSL_VERIFY,
                timeout=15,
            )
            if resp.status_code == 200:
                apps_list = resp.json()
                catalog = {}
                for app in apps_list:
                    name = app.get("name", "")
                    actions = app.get("actions", [])
                    action_data = []
                    for a in actions:
                        if isinstance(a, dict):
                            # We need the 'name' field which is the internal identifier
                            action_data.append({
                                "name": a.get("name", ""),
                                "description": a.get("description", "")
                            })

                    catalog[name] = {
                        "id": app.get("id", ""),
                        "version": app.get("app_version", "1.1.0"),
                        "actions": action_data,
                    }
                self._catalog = catalog
                console.print(f"[dim]  → Discovered {len(catalog)} apps from Shuffle API[/dim]")
                return self._catalog
        except Exception as e:
            console.print(f"[red]  → Discovery failed: {e}. Using internal fallback.[/red]")
            # Minimal fallback if API is down
            self._catalog = {
                "Virustotal_v3": {"id": "fa9d7dd6d5e501798870c9451611817f", "version": "1.1.0", "actions": [{"name": "get_a_hash_report_"}]},
                "http": {"id": "4c2060fe-17ec-4486-ae26-fa6918dfb53f", "version": "1.4.0", "actions": [{"name": "GET"}, {"name": "POST"}]},
                "TheHive": {"id": "32eee57aa08d90614d8f442ea0830f9d", "version": "1.1.0", "actions": [{"name": "post_create_case_from_alert"}]},
                "Shuffle Tools": {"id": "0e7cedbb-417a-43b0-b62c-ba36194e0543", "version": "1.2.0", "actions": [{"name": "regex_capture_group"}]}
            }
        return self._catalog

    def build_prompt_section(self, keywords: List[str]) -> str:
        lines = ["## INSTALLED APPS (Use EXACT internal names for 'name' field)\n"]
        for name, data in self._catalog.items():
            # Only include relevant apps to save tokens
            if keywords and not any(k.lower() in name.lower() for k in keywords):
                if name not in ["http", "Shuffle Tools"]: continue

            lines.append(f"### App: \"{name}\"")
            lines.append(f"  app_id: \"{data['id']}\"")
            lines.append(f"  app_version: \"{data['version']}\"")
            lines.append(f"  VALID ACTIONS (Use one of these in the 'name' field):")
            for action in data["actions"]:
                lines.append(f"    - \"{action['name']}\" ({action['description'][:60]}...)")
            lines.append("")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — Cyber Context Injector
# ══════════════════════════════════════════════════════════════════════════════

class CyberContextInjector:
    def __init__(self, prompt: str):
        self.prompt = prompt

    def get_keywords(self) -> List[str]:
        keys = ["virustotal", "thehive", "wazuh", "misp", "cortex", "http", "threat"]
        return [k for k in keys if k in self.prompt.lower()]

    def build_context(self) -> str:
        context = "## Context Information\n"
        if "554" in self.prompt:
            context += "- Wazuh Rule 554 = File Added to System. Alert fields: syscheck.path, syscheck.sha256_after, agent.id, agent.name.\n"
        if "delete" in self.prompt.lower() or "active response" in self.prompt.lower():
            context += "- Wazuh Active Response requires two steps with the 'http' app:\n"
            context += f"  1. Auth: GET {config.WAZUH_API_URL}/security/user/authenticate (Basic Auth)\n"
            context += f"  2. Command: POST {config.WAZUH_API_URL}/active-response (Bearer Token). Body: {{\"command\": \"delete-file\", \"arguments\": [\"$exec.body.syscheck.path\"], \"alert\": {{}}, \"agent_list\": [\"$exec.body.agent.id\"]}}\n"
        return context


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — OpenAI Workflow Engine
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a Shuffle SOAR expert. Generate a workflow JSON.

# CRITICAL RULES (MAPPING):
1. 'name': This field MUST be the EXACT internal action identifier (e.g. "get_a_hash_report_", "GET", "POST"). 
2. 'label': This field is for your descriptive name (e.g. "VirusTotal Report", "Wazuh Auth").
3. Variable Referencing: To reference a previous node, use the snake_case version of its LABEL.
   Example: If a node has label "VirusTotal Report", reference its data as $virustotal_report.data.attributes...
4. Metadata: Use app_id and app_version correctly from the catalog.

# STRUCTURE:
{
  "name": "descriptive_name",
  "description": "...",
  "start": "webhook_trigger",
  "triggers": [
    {
      "id": "webhook_trigger",
      "name": "Wazuh Webhook",
      "app_name": "Shuffle Tools",
      "app_version": "1.2.0",
      "trigger_type": "WEBHOOK",
      "label": "Wazuh Alert Webhook",
      "status": "running"
    }
  ],
  "actions": [
    {
      "id": "action_<uuid>",
      "name": "<INTERNAL_ACTION_NAME>",
      "label": "<DESCRIPTIVE_LABEL>",
      "app_name": "<APP_NAME>",
      "app_id": "<APP_ID>",
      "app_version": "<APP_VERSION>",
      "parameters": [{"name": "...", "value": "..."}]
    }
  ],
  "branches": [
    {
      "id": "branch_<uuid>",
      "source_id": "...",
      "destination_id": "...",
      "label": "...",
      "conditions": [
        {
          "condition": {
            "source": {"type": "value", "value": "$<slugified_label>.data..."},
            "operator": "LARGER_THAN",
            "destination": {"type": "value", "value": "0"}
          }
        }
      ]
    }
  ]
}
"""

class OpenAIWorkflowEngine:
    def __init__(self):
        self.api_key = config.OPENAI_API_KEY

    def generate(self, user_prompt: str, catalog: str, context: str) -> Dict:
        full_user_msg = f"{context}\n\n## Catalog\n{catalog}\n\n## Request\n{user_prompt}"
        
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": full_user_msg}
                ],
                "temperature": 0
            },
            timeout=60
        )
        
        if resp.status_code != 200:
            raise Exception(f"OpenAI Error: {resp.text}")
            
        content = resp.json()["choices"][0]["message"]["content"]
        # Clean markdown
        content = re.sub(r"```json\s*", "", content)
        content = re.sub(r"\s*```", "", content)
        return json.loads(content.strip())


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — Shuffle Importer
# ══════════════════════════════════════════════════════════════════════════════

class ShuffleImporter:
    def import_wf(self, wf: Dict):
        console.print(f"\n[bold green]Pushing workflow '{wf['name']}' to Shuffle...[/bold green]")
        resp = requests.post(
            f"{config.SHUFFLE_URL}/api/v1/workflows",
            headers={"Authorization": f"Bearer {config.SHUFFLE_API_KEY}"},
            json=wf,
            verify=config.SSL_VERIFY,
            timeout=20
        )
        if resp.status_code in [200, 201]:
            data = resp.json()
            console.print(f"✅ Success! Workflow ID: {data.get('id')}")
            console.print(f"🔗 URL: {config.SHUFFLE_URL}/workflows/{data.get('id')}")
        else:
            console.print(f"❌ Failed: {resp.status_code} - {resp.text}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

def main():
    console.print(Panel("[bold cyan]Shuffle SOC Factory v4.0[/bold cyan]"))
    
    # 1. Discovery
    discovery = ShuffleAppDiscovery()
    discovery.load()
    
    # 2. Input
    if len(sys.argv) > 1:
        user_prompt = " ".join(sys.argv[1:])
    else:
        user_prompt = "Detect file added (rule 554), VT scan, delete file via Wazuh API if malicious, open TheHive case."

    # 3. Context & Catalog building
    injector = CyberContextInjector(user_prompt)
    context = injector.build_context()
    catalog_str = discovery.build_prompt_section(injector.get_keywords())
    
    # 4. GPT-4 Generation
    console.print("\n[bold yellow]Generating Workflow JSON...[/bold yellow]")
    engine = OpenAIWorkflowEngine()
    workflow = engine.generate(user_prompt, catalog_str, context)
    
    # 5. Review JSON
    console.print("\n[bold]Generated JSON Preview:[/bold]")
    console.print(Syntax(json.dumps(workflow, indent=2), "json", theme="monokai"))
    
    # 6. Import
    importer = ShuffleImporter()
    importer.import_wf(workflow)

if __name__ == "__main__":
    main()
