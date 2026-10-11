"""Fail closed on unreviewed Cargo licenses and produce redistribution notices."""
import argparse
import json
from pathlib import Path
import subprocess

REVIEWED = {
    "MIT", "MIT OR Apache-2.0", "Apache-2.0 OR MIT", "MIT/Apache-2.0",
    "MIT OR Apache-2.0 OR LGPL-2.1-or-later", "Unlicense OR MIT",
    "BSD-3-Clause", "(MIT OR Apache-2.0) AND Unicode-3.0",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    metadata = json.loads(subprocess.check_output([args.cargo, "metadata", "--locked",
        "--manifest-path", str(root / "Cargo.toml"), "--format-version", "1"], text=True))
    output = ["TLS20 ITS third-party notices\nMIT options elected; no GPL/LGPL option elected.\n"]
    for package in sorted(metadata["packages"], key=lambda p:(p["name"],p["version"])):
        if package["name"] == "tls20-its":
            continue
        expression = package.get("license")
        if expression not in REVIEWED:
            raise SystemExit(f"Unreviewed license: {package['name']}: {expression}")
        folder = Path(package["manifest_path"]).parent
        files = [p for p in folder.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE"))]
        selected = [p for p in files if "MIT" in p.name.upper()]
        if not selected:
            selected = [p for p in files if p.name.upper() in ("LICENSE", "LICENSE.TXT", "LICENSE.MD", "LICENCE")]
        if package["name"] == "rasn-its":
            selected = [root / "vendor" / "rasn" / "LICENCE-MIT"]
        if package["name"] == "r-efi":
            # Upstream publishes its complete MIT election in AUTHORS.
            selected = [folder / "AUTHORS"]
        if "Unicode-3.0" in expression:
            selected += [folder / "LICENSE-UNICODE"]
        if not selected:
            raise SystemExit(f"Missing reviewed notice: {package['name']}")
        output.append(f"\n=== {package['name']} {package['version']} ===\nSPDX: {expression}\n")
        output.append("Selected: " + ("BSD-3-Clause" if expression == "BSD-3-Clause" else
                                       "MIT + Unicode-3.0" if "Unicode" in expression else "MIT") + "\n")
        for file in sorted(set(selected)):
            text = file.read_text(encoding="utf8")
            if not text.strip():
                raise SystemExit(f"Empty license: {file}")
            output.append(text.strip() + "\n")
    (root / "THIRD_PARTY_NOTICES.txt").write_text("\n".join(output), encoding="utf8", newline="\n")
    print(f"Reviewed {len(metadata['packages'])-1} dependency licenses; notices generated.")


if __name__ == "__main__":
    main()
