"""Install the built wheel in an isolated environment and exercise its CLI.

Dependencies are fetched by pip, just as for a normal installation. No listener
is opened, and generated test credentials disappear with the temporary folder.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import venv
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    wheels = list(root.joinpath("dist").glob("tls20_server-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/; use a clean build output.")
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert "tls20_server/handshake.py" in names
        assert any(name.endswith("/entry_points.txt") for name in names)
        assert not any(name.endswith((".pem", ".key", ".pfx", ".p12")) for name in names)
    with tempfile.TemporaryDirectory(prefix="tls20-wheel-") as temporary:
        directory = Path(temporary)
        environment = directory / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        cli = scripts / ("tls20-server.exe" if os.name == "nt" else "tls20-server")
        clean_env = dict(os.environ)
        clean_env.pop("PYTHONPATH", None)
        clean_env.pop("PYTHONHOME", None)

        def run(*arguments):
            return subprocess.run([str(argument) for argument in arguments], cwd=directory,
                                  env=clean_env, check=True, timeout=180)

        run(python, "-m", "pip", "install", wheel)
        run(cli, "--version")
        run(python, "-m", "tls20_server", "lab-init", "--directory", "lab")
        run(cli, "check-config", "--config", "lab/server.toml")
        run(python, "-c", "import tls20_server; from pathlib import Path; "
            "assert Path(tls20_server.__file__).resolve().is_relative_to(Path('environment').resolve())")
    print("Wheel installed and CLI validated outside the source checkout.")


if __name__ == "__main__":
    main()
