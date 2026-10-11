"""Install the built wheel in an isolated environment and exercise its CLI.

Dependencies are fetched by pip, just as for a normal installation. No listener
is opened, and generated test credentials disappear with the temporary folder.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import venv
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    wheels = list(root.joinpath("dist").glob("tls20_server-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in dist/; use a clean build output.")
    wheel = wheels[0]
    sources = list(root.joinpath("dist").glob("tls20_server-*.tar.gz"))
    if len(sources) != 1:
        raise SystemExit("Expected exactly one matching source archive in dist/.")
    with tarfile.open(sources[0], "r:gz") as archive:
        names = archive.getnames()
        for required in ("native/its/Cargo.toml", "native/its/Cargo.lock",
                         "native/its/src/lib.rs", "native/its/vendor/rasn/src/oer/de.rs",
                         "native/its/vendor/rasn/LICENCE-MIT", "native/its/vendor/rasn/LICENCE-APACHE",
                         "native/its/THIRD_PARTY_NOTICES.txt", "native/its/check_licenses.py",
                         "tools/build_native_dependencies.py", "tools/getdns_msvc/strings.h"):
            assert any(name.endswith('/' + required) for name in names), required
        assert not any('/native/its/target/' in name for name in names)
        assert not any(name.endswith((".dll", ".so", ".dylib", ".pem", ".key", ".pfx", ".p12")) for name in names)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert "tls20_server/handshake.py" in names
        assert b"TEST_DIAGNOSTICS = False" in archive.read("tls20_server/_build_features.py")
        assert any(name.endswith("/entry_points.txt") for name in names)
        assert any(name.endswith("/share/tls20-server/native/pake.c") for name in names)
        assert any(name.endswith("/share/tls20-server/native/CMakeLists.txt") for name in names)
        assert not any(name.endswith((".dll", ".so", ".dylib")) for name in names)
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
