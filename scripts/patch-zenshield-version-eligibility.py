"""Keep signed ZenShield releases separate from legacy git-hash updater versions."""
import ast
import sys
from pathlib import Path
path=Path(sys.argv[1])/'ota/services.py'
text=path.read_text()
guard="    if target_product == 'zenai' and not __import__('re').fullmatch(r'[0-9]+\\.[0-9]+\\.[0-9]+', appliance.current_version or ''):\n        return None  # Signed ZenShield packages require a compatible semantic-version client.\n\n"
anchor='    # 1. Find latest published release'
if guard not in text:
    assert text.count(anchor)==1
    text=text.replace(anchor,guard+anchor)
ast.parse(text);path.write_text(text)
