"""
Vite manifest reader for Jinja2 template asset loading.

Reads the build manifest to generate correct fingerprinted asset URLs.
Falls back to source paths in development mode.
"""

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_manifest: Optional[dict] = None
_MANIFEST_PATH = Path(__file__).parent.parent / "static" / "dist" / ".vite" / "manifest.json"


def _load_manifest() -> dict:
    global _manifest
    if _manifest is not None:
        return _manifest
    try:
        with open(_MANIFEST_PATH) as f:
            _manifest = json.load(f)
            logger.info(f"Vite manifest loaded: {len(_manifest)} entries")
    except FileNotFoundError:
        logger.warning("Vite manifest not found — run 'npm run build' first")
        _manifest = {}
    return _manifest


def vite_asset(src: str) -> str:
    """Get the fingerprinted URL for a Vite-built asset.

    Usage in Jinja2: {{ vite_asset('static/src/main.css') }}
    Returns: /static/dist/css/main-5f2oErbd.css
    """
    manifest = _load_manifest()
    entry = manifest.get(src)
    if entry:
        return f"/static/dist/{entry['file']}"
    return f"/{src}"
