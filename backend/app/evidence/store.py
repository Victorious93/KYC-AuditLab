"""Write evidence files under the configured evidence dir, redacted first."""
from __future__ import annotations

import os
import re

from .redact import redact

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def write_evidence(evidence_dir: str, name: str, content: str) -> str:
    """Redact `content` and write it to `<evidence_dir>/<sanitized name>`.
    Returns the path. Files are created 0600 (owner-only)."""
    os.makedirs(evidence_dir, exist_ok=True)
    safe = _SAFE.sub("_", os.path.basename(name)) or "evidence.txt"
    path = os.path.join(evidence_dir, safe)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(redact(content) or "")
    return path
