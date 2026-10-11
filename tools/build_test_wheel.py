"""Build an explicitly labeled diagnostic test wheel without editing the checkout."""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description="Build a TEST-DATA-ONLY wheel with local key-log capability.")
    parser.add_argument("--authorize-test-diagnostics", action="store_true", required=True)
    parser.add_argument("--outdir", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    out = args.outdir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tls20-diagnostic-build-") as temporary:
        stage = Path(temporary)
        shutil.copytree(source / "tls20_server", stage / "tls20_server", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copy2(source / name, stage / name)
        (stage / "native").mkdir()
        for name in ("pake.c", "CMakeLists.txt"):
            shutil.copy2(source / "native" / name, stage / "native" / name)
        # Generated build output only. The ordinary source and wheel remain off.
        (stage / "tls20_server" / "_build_features.py").write_text(
            '"""TEST DATA ONLY. Explicit diagnostic build; never deploy to production."""\nTEST_DIAGNOSTICS = True\n',
            encoding="utf-8")
        metadata = (stage / "pyproject.toml").read_text(encoding="utf-8")
        metadata = metadata.replace('name = "tls20-server"', 'name = "tls20-server-test-diagnostics"', 1)
        (stage / "pyproject.toml").write_text(metadata, encoding="utf-8")
        subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(out)], cwd=stage, check=True)
    print("Built diagnostic TEST wheel. Local sink and separate category authorization are still required.")


if __name__ == "__main__":
    main()
