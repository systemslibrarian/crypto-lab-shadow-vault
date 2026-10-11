"""Compile immutable current Rust inputs twice; retain honest artifact provenance."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARTIFACTS = ('shadow_vault_crypto.js', 'shadow_vault_crypto_bg.wasm')
RUST_COMMIT = '17067e9ac6d7ecb70e50f92c1944e545188d2359'
TOOLS = {
    ('Darwin', 'arm64'): (
        ('wasm-pack', '0.15.0', 'wasm-pack/v0.15.0', 'wasm-pack-v0.15.0-aarch64-apple-darwin.tar.gz',
         '0abff4a03d670b6c00ea31d0e1608a72407e355f3d3765e9c30eb45cd5b7e318'),
        ('wasm-bindgen', '0.2.117', 'wasm-bindgen/0.2.117', 'wasm-bindgen-0.2.117-aarch64-apple-darwin.tar.gz',
         'd7691b221163d68884ef0a893cb57d3372f1100789dbf0cc2c9260a7f253a497')),
    ('Linux', 'x86_64'): (
        ('wasm-pack', '0.15.0', 'wasm-pack/v0.15.0', 'wasm-pack-v0.15.0-x86_64-unknown-linux-musl.tar.gz',
         'c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a'),
        ('wasm-bindgen', '0.2.117', 'wasm-bindgen/0.2.117', 'wasm-bindgen-0.2.117-x86_64-unknown-linux-musl.tar.gz',
         '97f527f7c7956f69a88a4bdb5176142ebc4e255c2dbe3805ec4f373421028240')),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_command(command, cwd, env, report, save, timeout=600):
    row = dict(command=command, startedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    started = time.monotonic()
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        row.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        row.update(exit=None, timedOut=True, stdout=text(error.stdout), stderr=text(error.stderr))
        raise RuntimeError('Command timed out: ' + ' '.join(command)) from error
    finally:
        row.update(finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(), seconds=time.monotonic()-started)
        report['commands'].append(row)
        save()
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(command))
    return result.stdout.strip()


def validate_compiler(identity):
    fields = {}
    for line in identity.splitlines()[1:]:
        if ': ' not in line:
            raise RuntimeError('Malformed actual compiler identity')
        key, value = line.split(': ', 1)
        if key in fields:
            raise RuntimeError('Ambiguous actual compiler identity')
        fields[key] = value
    if not identity.startswith('rustc 1.87.0 (17067e9ac ') or fields.get('release') != '1.87.0' or fields.get('commit-hash') != RUST_COMMIT or not fields.get('host') or not fields.get('LLVM version'):
        raise RuntimeError('Unexpected actual Rust compiler')


def unpack_verified(archive, expected, destination):
    if digest(archive.read_bytes()) != expected:
        raise RuntimeError('Tool archive hash mismatch; refusing execution')
    with tarfile.open(archive) as bundle:
        for item in bundle.getmembers():
            path = pathlib.PurePosixPath(item.name)
            if path.is_absolute() or '..' in path.parts or not (item.isdir() or item.isfile()):
                raise RuntimeError('Unsafe tool archive member')
        bundle.extractall(destination, filter='data')


def compare_artifacts(first, second):
    rows = []
    for name in ARTIFACTS:
        a, b = (first / name).read_bytes(), (second / name).read_bytes()
        if not a or not b:
            raise RuntimeError('Empty build artifact: ' + name)
        if name.endswith('.wasm') and (a[:8] != b'\0asm\x01\0\0\0' or b[:8] != b'\0asm\x01\0\0\0'):
            raise RuntimeError('Malformed WASM artifact')
        if a != b:
            raise RuntimeError('Independent clean builds differ: ' + name)
        rows.append(dict(path=name, bytes=len(a), sha256=digest(a), repeatMatches=True))
    return rows


def registry_packages(lockfile):
    packages = tomllib.loads(lockfile.read_text()).get('package')
    if not isinstance(packages, list) or not packages:
        raise RuntimeError('Incomplete Cargo lock')
    rows = []
    for package in packages:
        if package.get('source') is None:
            continue
        checksum = package.get('checksum', '')
        if package['source'] != 'registry+https://github.com/rust-lang/crates.io-index' or len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum):
            raise RuntimeError('Unsupported or incomplete dependency provenance')
        rows.append(dict(name=package['name'], version=package['version'], checksum=checksum))
    return rows


def verify_registry_archives(packages, cargo_home):
    for package in packages:
        filename = package['name'] + '-' + package['version'] + '.crate'
        matches = list((cargo_home / 'registry/cache').glob('*/' + filename))
        if len(matches) != 1 or digest(matches[0].read_bytes()) != package['checksum']:
            raise RuntimeError('Missing or changed locked dependency archive: ' + filename)


def capture_source(root, destination):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args])
    sha = git('rev-parse', 'HEAD').decode().strip()
    if len(sha) != 40 or any(c not in '0123456789abcdef' for c in sha):
        raise RuntimeError('Invalid source SHA')
    if git('status', '--porcelain', '--untracked-files=all', '--', 'crate', 'rust-toolchain.toml'):
        raise RuntimeError('Uncommitted Rust inputs; commit reviewed source before reproduction')
    tree = git('ls-tree', '-r', '-z', sha, '--', 'crate', 'rust-toolchain.toml')
    rows = []
    for entry in tree.split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, kind, blob = header.decode().split()
        name = name.decode()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise RuntimeError('Unsupported source object: ' + name)
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts:
            raise RuntimeError('Unsafe tracked source path')
        data = git('cat-file', 'blob', blob)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rows.append(dict(path=name, gitBlob=blob, sha256=digest(data)))
    required = {'crate/Cargo.toml', 'crate/Cargo.lock', 'crate/src/lib.rs', 'rust-toolchain.toml'}
    if not required <= {row['path'] for row in rows}:
        raise RuntimeError('Incomplete source inputs')
    return sha, rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', type=pathlib.Path)
    args = parser.parse_args()
    output = ROOT / 'pkg'
    if output.is_symlink():
        raise RuntimeError('Refusing a symlinked output directory')
    output.mkdir(exist_ok=True)
    receipt = args.receipt or output / 'wasm-provenance.json'
    report = dict(startedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  state='incomplete', sourceSha=None, originalCompiler=None,
                  platform=dict(system=platform.system(), machine=platform.machine()), commands=[],
                  scope='Two clean builds of current immutable Rust source; historical binaries and live deployment require separate comparisons.')
    recipe_hash = digest(pathlib.Path(__file__).read_bytes())
    report['recipeSha256'] = recipe_hash
    def save():
        receipt.write_text(json.dumps(report, indent=2) + '\n')
    def run(command, cwd, env):
        return run_command(command, cwd, env, report, save)
    save()
    try:
        specs = TOOLS.get((platform.system(), platform.machine()))
        if not specs:
            raise RuntimeError('Unsupported build host; no unverified fallback')
        with tempfile.TemporaryDirectory(prefix='shadow-wasm-reproduction-') as temporary:
            work = pathlib.Path(temporary)
            source = work / 'source'
            report['sourceSha'], report['sourceInputs'] = capture_source(ROOT, source)
            report['registryPackages'] = registry_packages(source / 'crate/Cargo.lock')
            # Do not inherit repository/user Cargo configuration, wrappers or secrets.
            env = {key: os.environ[key] for key in ('PATH', 'HOME', 'RUSTUP_HOME', 'TMPDIR') if key in os.environ}
            cargo_home = work / 'cargo-home'
            env.update(CARGO_HOME=str(cargo_home), CARGO_INCREMENTAL='0', CARGO_TERM_COLOR='never',
                       RUSTUP_TOOLCHAIN='1.87.0', RUSTFLAGS='--remap-path-prefix=' + str(cargo_home) + '=/fleet/cargo')
            tool_rows, binaries = [], {}
            for name, version, release, filename, expected in specs:
                repository, tag = release.split('/')
                url = 'https://github.com/wasm-bindgen/' + repository + '/releases/download/' + tag + '/' + filename
                archive = work / filename
                with urllib.request.urlopen(url, timeout=60) as response:
                    payload = response.read()
                archive.write_bytes(payload)
                dest = work / name
                dest.mkdir()
                unpack_verified(archive, expected, dest)
                matches = [path for path in dest.rglob(name) if path.is_file()]
                if len(matches) != 1:
                    raise RuntimeError('Incomplete pinned tool archive: ' + name)
                binary = matches[0]
                observed = run([str(binary), '--version'], work, env)
                if observed != name + ' ' + version:
                    raise RuntimeError('Unexpected pinned tool version: ' + observed)
                binaries[name] = binary
                tool_rows.append(dict(name=name, version=observed, url=url, archiveSha256=expected,
                                      binarySha256=digest(binary.read_bytes())))
            env['PATH'] = os.pathsep.join(str(binaries[name].parent) for name in ('wasm-pack', 'wasm-bindgen')) + os.pathsep + env['PATH']
            report['tools'] = tool_rows
            rustup = shutil.which('rustup', path=env['PATH'])
            if not rustup and env.get('HOME'):
                candidate = pathlib.Path(env['HOME']) / '.cargo/bin/rustup'
                if candidate.is_file():
                    rustup = str(candidate)
            if not rustup:
                raise RuntimeError('rustup is required; refusing an unrelated system compiler')
            run([rustup, 'toolchain', 'install', '1.87.0', '--profile', 'minimal',
                 '--target', 'wasm32-unknown-unknown', '--no-self-update'], source, env)
            compiler_path = run([rustup, 'which', 'rustc', '--toolchain', '1.87.0'], source, env)
            cargo_path = run([rustup, 'which', 'cargo', '--toolchain', '1.87.0'], source, env)
            env['PATH'] = str(pathlib.Path(cargo_path).parent) + os.pathsep + env['PATH']
            env['RUSTC'] = compiler_path
            compiler = run([compiler_path, '-vV'], source, env)
            validate_compiler(compiler)
            report['compiler'] = dict(identity=compiler, path=compiler_path,
                                      executableSha256=digest(pathlib.Path(compiler_path).read_bytes()))
            report['cargo'] = dict(identity=run([cargo_path, '-V'], source, env), path=cargo_path,
                                  executableSha256=digest(pathlib.Path(cargo_path).read_bytes()))
            report['buildFlags'] = dict(rustflags=env['RUSTFLAGS'], target='wasm32-unknown-unknown',
                                        profile='release', locked=True, offlineBuild=True, installMode='no-install')
            run(['cargo', 'fetch', '--locked', '--manifest-path', 'crate/Cargo.toml'], source, env)
            verify_registry_archives(report['registryPackages'], cargo_home)
            for label in ('first', 'second'):
                target = work / ('target-' + label)
                if target.exists():
                    raise RuntimeError('Build target was not fresh')
                env['CARGO_TARGET_DIR'] = str(target)
                run([str(binaries['wasm-pack']), 'build', 'crate', '--mode', 'no-install', '--target', 'web',
                     '--out-dir', str(work / label), '--release', '--', '--locked', '--offline'], source, env)
            report['artifacts'] = compare_artifacts(work / 'first', work / 'second')
            report['trackedArtifactComparisons'] = []
            for row in report['artifacts']:
                tracked = subprocess.check_output(['git', '-C', str(ROOT), 'show', report['sourceSha'] + ':public/' + row['path']])
                report['trackedArtifactComparisons'].append(dict(path=row['path'], trackedSha256=digest(tracked),
                                                               rebuiltSha256=row['sha256'], matches=tracked == (work / 'first' / row['path']).read_bytes()))
            if subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip() != report['sourceSha']:
                raise RuntimeError('Repository SHA changed during reproduction')
            if digest(pathlib.Path(__file__).read_bytes()) != recipe_hash or subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all', '--', 'crate', 'rust-toolchain.toml']):
                raise RuntimeError('Recipe or Rust inputs changed during reproduction')
            # Publish only outputs that survived the pair comparison, never stale pkg.
            for name in ARTIFACTS:
                target = output / name
                if target.is_symlink():
                    raise RuntimeError('Refusing a symlinked artifact destination')
            for name in ARTIFACTS:
                shutil.copyfile(work / 'first' / name, output / name)
            for path in (work / 'first').glob('*.d.ts'):
                if (output / path.name).is_symlink():
                    raise RuntimeError('Refusing a symlinked generated type destination')
                shutil.copyfile(path, output / path.name)
            report['state'] = 'reproduced-current-source'
    except BaseException as error:
        report['state'] = 'failed'
        report['error'] = str(error)
        raise
    finally:
        report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(json.dumps(dict(state=report['state'], sourceSha=report['sourceSha'], artifacts=report['artifacts'],
                          trackedArtifactComparisons=report['trackedArtifactComparisons'], receipt=str(receipt))))


if __name__ == '__main__':
    main()
