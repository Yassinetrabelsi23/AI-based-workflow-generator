"""
config.py — Shuffle SOC Factory
Charge et expose toutes les variables de configuration depuis .env
"""

import os
import warnings

# Supprime les warnings SSL pour les instances locales self-signed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from dotenv import load_dotenv

# Charge le fichier .env situé dans le même répertoire que ce script
_env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=_env_path, override=True)

# ── Shuffle ────────────────────────────────────────────────────────────────────
SHUFFLE_URL: str = os.getenv("SHUFFLE_URL", "https://10.5.1.119:3443").rstrip("/")
SHUFFLE_API_KEY: str = os.getenv("SHUFFLE_API_KEY", "")

# ── OpenAI (legacy — kept for reference) ──────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

# ── Ollama (local LLM backend) ─────────────────────────────────────────────────
OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "mistral")

# ── Wazuh REST API ─────────────────────────────────────────────────────────────
WAZUH_API_URL: str = os.getenv("WAZUH_API_URL", "https://10.5.1.115:55000").rstrip("/")
WAZUH_API_USER: str = os.getenv("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS: str = os.getenv("WAZUH_API_PASS", "")

# ── Options globales ───────────────────────────────────────────────────────────
SSL_VERIFY: bool = False          # Instance locale — certificat auto-signé

# ── Validation rapide au démarrage ────────────────────────────────────────────
def validate_config() -> list[str]:
    """Retourne la liste des variables manquantes (critiques)."""
    missing = []
    if not SHUFFLE_API_KEY:
        missing.append("SHUFFLE_API_KEY")
    if not WAZUH_API_PASS:
        missing.append("WAZUH_API_PASS")
    return missing
