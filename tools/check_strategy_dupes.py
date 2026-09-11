#!/usr/bin/env python3
"""Fail CI if any two strategy YAML files share identical normalized content."""
import hashlib, re, sys
from collections import defaultdict
from pathlib import Path

def normalize(text: str) -> str:
    text = re.sub(r'(id|name):\s*.*', '', text)
    return re.sub(r'\s+', '', text)

root = Path(__file__).parent.parent / "src/hdwp/core/exploit/strategies"
seen: dict[str, list[Path]] = defaultdict(list)
for f in sorted(root.rglob("*.yaml")):
    h = hashlib.sha256(normalize(f.read_text()).encode()).hexdigest()
    seen[h].append(f)

dupes = {h: files for h, files in seen.items() if len(files) > 1}
if dupes:
    for files in dupes.values():
        print(f"DUPLICATE ({len(files)} files): {[str(f) for f in files]}")
    sys.exit(1)

print(f"OK — {len(seen)} unique strategies")
