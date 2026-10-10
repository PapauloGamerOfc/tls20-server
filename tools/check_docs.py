"""Check repository-relative Markdown file links without following web URLs."""

from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


def main():
    root = Path(__file__).resolve().parents[1]
    failures = []
    for file in [*root.glob("*.md"), *root.joinpath("docs").rglob("*.md")]:
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", file.read_text(encoding="utf-8")):
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            path = (file.parent / unquote(url.path)).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                failures.append(f"{file.relative_to(root)}: missing/unsafe local link {target}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Local documentation file links validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
