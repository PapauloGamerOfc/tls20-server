"""Explicit reproducible test-provider build, never run by the server at startup.

All code is pinned: OpenSSL (Apache-2.0), GOST provider (Apache-2.0/CC0),
optional getdns (BSD-3-Clause, stub-only, without LGPL libidn2), and the
locked permissively licensed ITS helper. Requires git, CMake, Perl, a native
C compiler and (with ITS) Rust. No global installation,
trust-store changes, secrets, service launch or binary download is performed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

OPENSSL_REVISION = '286ddeaac037533bbdce65b3c689e3f7ffebf0f6'  # openssl-3.5.6
GOST_REVISION = '4632029f872981c9f969f1cee8b4fb590dab598b'
GETDNS_REVISION = 'f8c95b4f150a7b42153a380fea05ed6ad5ce9826'


def verify_pinned_source(source, revision, capture):
    if capture('git', '-C', source, 'rev-parse', 'HEAD') != revision:
        raise SystemExit(f'Refusing to overwrite source at another revision: {source}')
    # Build systems can execute untracked/ignored configuration files as well
    # as tracked ones. Reuse only pristine sources; never clean a user's tree.
    if capture('git', '-C', source, 'status', '--porcelain',
               '--untracked-files=all', '--ignored=matching', '--ignore-submodules=none'):
        raise SystemExit(f'Refusing modified or extra source files: {source}; use a new clean source directory')


def find_one(directory, pattern):
    # Unix shared-library version aliases may all name the same file. Reject
    # ambiguous stale configurations instead of choosing an arbitrary binary.
    found = sorted({path.resolve() for path in directory.rglob(pattern) if path.is_file()})
    if len(found) != 1:
        raise SystemExit(f'Expected one {pattern} in {directory}, found {found}')
    return found[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--openssl-source', type=Path, help='Reuse this exact clean pinned source without fetching')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--with-gost', action='store_true')
    parser.add_argument('--with-getdns', action='store_true')
    parser.add_argument('--with-its', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32: parser.error('--jobs must be between 1 and 32')
    output = args.output.resolve()
    if output == Path(output.anchor) or output == Path.home(): parser.error('output must be a dedicated build directory')
    output.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    log_path = output/'build.log'
    manifest = {'revisions': {'openssl': OPENSSL_REVISION}, 'environment': {}}

    def argv(command):
        values = [str(item) for item in command]
        values[0] = shutil.which(values[0], path=environment.get('PATH')) or values[0]
        return values

    def capture(*command, cwd=None):
        return subprocess.check_output(argv(command), cwd=cwd,
            env=environment, text=True, encoding='utf-8', errors='replace').strip()

    def run(*command, cwd=None):
        print('Running:', ' '.join(str(item) for item in command), flush=True)
        with log_path.open('a', encoding='utf-8') as log:
            log.write('\nCOMMAND '+repr([str(item) for item in command])+'\n'); log.flush()
            result = subprocess.run(argv(command), cwd=cwd,
                env=environment, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            print('\n'.join(log_path.read_text(encoding='utf-8',errors='replace').splitlines()[-35:]), file=sys.stderr)
            raise SystemExit(f'Build failed ({result.returncode}); retained log: {log_path}')

    def pinned_source(name, url, revision, override=None):
        source = override.resolve() if override else output/'sources'/name
        if not source.exists():
            if override:
                raise SystemExit(f'Explicit source does not exist: {source}')
            source.parent.mkdir(parents=True, exist_ok=True)
            run('git','init',source)
            run('git','-C',source,'remote','add','origin',url)
            run('git','-C',source,'fetch','--depth','1','origin',revision)
            run('git','-C',source,'checkout','--detach',revision)
        verify_pinned_source(source, revision, capture)
        return source

    if os.name == 'nt' and not shutil.which('cl', path=environment.get('PATH')):
        vswhere = Path(environment.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
        installation = capture(vswhere,'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath')
        batch = Path(installation)/'VC/Auxiliary/Build/vcvarsall.bat'
        if not batch.is_file(): raise SystemExit('Visual C++ build tools are required')
        environment['TLS20_BUILD_VCVARS'] = str(batch)
        # Keep the environment capture private: it may contain runner secrets.
        command = 'call "%TLS20_BUILD_VCVARS%" x64 >nul && set'
        # cmd.exe does not implement CommandLineToArgvW quoting. In particular,
        # subprocess.list2cmdline would turn the batch-path quotes into \".
        comspec = environment.get('COMSPEC','cmd.exe')
        result = subprocess.run(f'"{comspec}" /d /s /c "{command}"',
            env=environment,capture_output=True,text=True)
        if result.returncode: raise SystemExit('Could not initialize the Visual C++ build environment')
        for line in result.stdout.splitlines():
            key, separator, value = line.partition('=')
            if separator and key: environment[key.upper()] = value
        environment.pop('TLS20_BUILD_VCVARS',None)

    perl = shutil.which('perl',path=environment.get('PATH'))
    if not perl: raise SystemExit('Perl is required to build OpenSSL from source')
    # Git for Windows bundles a minimal Perl; prefer the complete interpreter
    # supplied on Windows CI when the caller did not already select one.
    if os.name == 'nt' and Path(r'C:\Strawberry\perl\bin\perl.exe').is_file():
        perl = r'C:\Strawberry\perl\bin\perl.exe'
    source = pinned_source('openssl','https://github.com/openssl/openssl.git',OPENSSL_REVISION,args.openssl_source)
    build, prefix = output/'openssl-build', output/'openssl'
    build.mkdir(exist_ok=True)
    configured = build/'Makefile'
    if configured.exists():
        source_line = next((line.partition('=')[2].strip() for line in
                            configured.read_text(encoding='utf-8').splitlines()
                            if line.startswith('SRCDIR=')), '')
        if not source_line or (build/source_line).resolve() != source:
            raise SystemExit('Existing OpenSSL build uses a different source path; '
                             'pass its exact --openssl-source or use a new output directory')
    if not configured.exists():
        target = ['VC-WIN64A'] if os.name == 'nt' else []
        run(perl,source/'Configure',*target,'shared','no-tests','no-docs','no-asm',
            f'--prefix={prefix}',f'--openssldir={prefix / "ssl"}','--libdir=lib',cwd=build)
    if os.name == 'nt':
        run('nmake','/NOLOGO',cwd=build); run('nmake','/NOLOGO','install_sw',cwd=build)
        library = prefix/'bin/libcrypto-3-x64.dll'
        executable = prefix/'bin/openssl.exe'
        environment['PATH'] = str(prefix/'bin')+os.pathsep+environment.get('PATH','')
    else:
        run('make',f'-j{args.jobs}',cwd=build); run('make','install_sw',cwd=build)
        library = prefix/('lib/libcrypto.3.dylib' if sys.platform == 'darwin' else 'lib/libcrypto.so.3')
        executable = prefix/'bin/openssl'
        loader = 'DYLD_LIBRARY_PATH' if sys.platform == 'darwin' else 'LD_LIBRARY_PATH'
        environment[loader] = str(prefix/'lib')+os.pathsep+environment.get(loader,'')
        manifest['environment'][loader] = environment[loader]
    if not library.is_file() or not executable.is_file(): raise SystemExit('OpenSSL installation missing expected binary')
    manifest['environment'].update(TLS20_TEST_OPENSSL=str(library),TLS20_TEST_OPENSSL_CLI=str(executable))
    manifest['openssl_prefix'] = str(prefix)

    def cmake(source, build, *options, target=None):
        run('cmake','-S',source,'-B',build,'-DCMAKE_BUILD_TYPE=Release',*options)
        targets = ['--target', target] if target else []
        run('cmake','--build',build,'--config','Release','--parallel',str(args.jobs),*targets)

    native = output/'pake'
    cmake(repo/'native',native,'-DTLS20_PWD_BUILD_TEST_ORACLE=ON')
    suffix = '.dll' if os.name == 'nt' else '.dylib' if sys.platform == 'darwin' else '.so'
    lib_prefix = '' if os.name == 'nt' else 'lib'
    manifest['environment']['TLS20_TEST_PAKE'] = str(find_one(native, f'{lib_prefix}tls20-pake{suffix}'))
    manifest['environment']['TLS20_TEST_PAKE_ORACLE'] = str(find_one(native, f'{lib_prefix}tls20-pake-oracle{suffix}'))

    if args.with_gost:
        source = pinned_source('gost-engine','https://github.com/gost-engine/engine.git',GOST_REVISION)
        run('git','-C',source,'submodule','update','--init','--depth','1')
        build = output/'gost'
        cmake(source,build,f'-DOPENSSL_ROOT_DIR={prefix}','-DGOST_BUILD_ENGINE=OFF',
            '-DGOST_BUILD_STATIC_ENGINE=OFF','-DGOST_BUILD_PROVIDER=ON',
            f'-DOPENSSL_ENGINES_DIR={prefix / "lib/engines-3"}', target='gost_prov')
        library = find_one(build,'gostprov.dll' if os.name == 'nt' else
                           'gostprov.dylib' if sys.platform == 'darwin' else 'gostprov.so')
        manifest['environment']['TLS20_TEST_GOST_MODULE'] = str(library)
        manifest['revisions']['gost'] = GOST_REVISION

    if args.with_getdns:
        source = pinned_source('getdns','https://github.com/getdnsapi/getdns.git',GETDNS_REVISION)
        run('git','-C',source,'submodule','update','--init','--depth','1','src/jsmn','src/yxml')
        build = output/'getdns'
        # Only two unconditional POSIX includes in upstream's gldns parser need
        # MSVC compatibility; retain pristine pinned upstream source. Existing
        # getdns config.h supplies function mappings and gettimeofday itself.
        compatibility = [f'-DCMAKE_C_FLAGS=/I"{repo / "tools/getdns_msvc"}"'] if os.name == 'nt' else []
        cmake(source,build,f'-DOPENSSL_ROOT_DIR={prefix}','-DENABLE_STUB_ONLY=ON','-DUSE_LIBIDN2=OFF',
            '-DENABLE_STATIC=OFF','-DENABLE_SHARED=ON','-DBUILD_TESTING=OFF',
            '-DBUILD_GETDNS_QUERY=OFF','-DBUILD_GETDNS_SERVER_MON=OFF','-DBUILD_STUBBY=OFF',
            '-DBUILD_LIBEV=OFF','-DBUILD_LIBEVENT2=OFF','-DBUILD_LIBUV=OFF',*compatibility)
        pattern = '*getdns.dll' if os.name == 'nt' else 'libgetdns.*.dylib' if sys.platform == 'darwin' else 'libgetdns.so.*.*.*'
        manifest['getdns'] = str(find_one(build,pattern))
        manifest['revisions']['getdns'] = GETDNS_REVISION
    if args.with_its:
        if not shutil.which('cargo', path=environment.get('PATH')):
            raise SystemExit('Rust/Cargo is required for the explicit ITS helper')
        native = output/'its'
        fixtures = output/'its-fixtures'
        fixtures.mkdir(exist_ok=True)
        environment['CARGO_TARGET_DIR'] = str(native)
        environment['TLS20_ITS_FIXTURE_DIR'] = str(fixtures)
        manifest['rust_toolchain'] = capture('rustc','--version')
        cargo_manifest = repo/'native/its/Cargo.toml'
        run(sys.executable,repo/'native/its/check_licenses.py')
        # Compile first so the generated short-lived fixtures are not already
        # expired by the time a cold release build completes.
        run('cargo','build','--manifest-path',cargo_manifest,'--locked','--release',
            '-j',str(args.jobs))
        run('cargo','test','--manifest-path',cargo_manifest,'--locked','--release',
            '-j',str(args.jobs))
        library = native/'release'/f'{lib_prefix}tls20_its{suffix}'
        if not library.is_file(): raise SystemExit('Missing built ITS helper')
        manifest['environment']['TLS20_TEST_ITS_LIBRARY'] = str(library)
        manifest['environment']['TLS20_ITS_FIXTURE_DIR'] = str(fixtures)
        # Consumers can explicitly regenerate expiring test fixtures without
        # introducing fixture-generation code into the production library.
        manifest['its_cargo_target'] = str(native)
    # Windows DLL dependency search is explicit in provider loaders. Stage only
    # the two OpenSSL runtime DLLs next to optional providers, not a PATH search.
    if os.name == 'nt':
        for key in ('getdns','gost'):
            value = manifest.get('getdns') if key == 'getdns' else manifest['environment'].get('TLS20_TEST_GOST_MODULE')
            if value:
                destination = Path(value).parent
                for name in ('libcrypto-3-x64.dll','libssl-3-x64.dll'):
                    shutil.copy2(prefix/'bin'/name,destination/name)
    path = output/'providers.json'
    path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(f'Provider manifest: {path}')


if __name__ == '__main__':
    main()
