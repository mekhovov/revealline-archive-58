"""Finite exact artifact inventory verification, including hidden files."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

from qualification_v2 import validate_waived

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 800_000_000
MARKER = b'{\n  "tool": "xonix-game-cli",\n  "formatVersion": 1\n}\n'
METADATA_NAMES = {'release.json', 'manifest.json', 'distribution.zip.sha256'}


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def inventory_for(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Artifact must be an ordinary directory')
    rows = []
    total = 0
    for base, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs:
            if (Path(base) / name).is_symlink():
                raise ValueError('Artifact directories cannot be links')
        for name in names:
            file = Path(base) / name
            info = file.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Artifact files cannot be links or special files')
            total += info.st_size
            if total > LIMIT or len(rows) >= 20000:
                raise ValueError('Artifact exceeds its finite budget')
            rows.append({'path': file.relative_to(directory).as_posix(), 'bytes': info.st_size, 'sha256': digest(file)})
    return sorted(rows, key=lambda row: row['path'])


def validate_rows(expected):
    seen = set()
    for row in expected:
        name = row['path']
        relative = PurePosixPath(name)
        if not name or relative.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')) or re.search(r'[\\\x00-\x1f\x7f:%?#]', name) or str(relative) != name or name in seen:
            raise ValueError('Unsafe/duplicate expected path')
        if type(row['bytes']) is not int or row['bytes'] < 0 or not re.fullmatch(r'[a-f0-9]{64}', row['sha256']):
            raise ValueError('Invalid inventory descriptor')
        seen.add(name)
    if len(expected) > 20000 or sum(row['bytes'] for row in expected) > LIMIT:
        raise ValueError('Expected inventory exceeds its finite budget')


def verify(directory, expected):
    validate_rows(expected)
    rows = inventory_for(directory)
    if rows != sorted(expected, key=lambda row: row['path']):
        raise ValueError('Artifact has missing, extra or changed files')
    return {'status': 'PASS', 'files': len(rows), 'bytes': sum(row['bytes'] for row in rows)}


def metadata_inventory(root, release):
    """Derive canonical expectations from pinned metadata, without fetching bodies."""
    version = release['version']
    if not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise ValueError('Invalid release version')
    metadata = root / 'metadata' / version
    if set(release['metadata']) != METADATA_NAMES:
        raise ValueError('Incomplete original metadata pins')
    for name, expected in release['metadata'].items():
        if digest(metadata / name) != expected:
            raise ValueError('Original metadata bytes changed: ' + version + '/' + name)
    record = json.loads((metadata / 'release.json').read_bytes())
    manifest = json.loads((metadata / 'manifest.json').read_bytes())
    if any(record[key] != release[key] for key in ('version', 'sourceRevision', 'distributionSha256')):
        raise ValueError('Original release identity changed')
    if record['manifestSha256'] != release['metadata']['manifest.json'] or any(manifest[key] != release[key] for key in ('version', 'sourceRevision')):
        raise ValueError('Original manifest identity changed')
    if (metadata / 'distribution.zip.sha256').read_bytes() != (release['distributionSha256'] + '  distribution.zip\n').encode():
        raise ValueError('Original checksum identity changed')
    rows = manifest['files']
    validate_rows(rows)
    reserved = METADATA_NAMES | {'.xonix-build.json', 'distribution.zip'}
    if any(row['path'] in reserved for row in rows) or sum(row['bytes'] for row in rows) != manifest['totalBytes']:
        raise ValueError('Manifest total or reserved path mismatch')
    prefix = 'releases/' + version + '/'
    result = [dict(row, path=prefix + 'site/' + row['path']) for row in rows]
    for name in sorted(METADATA_NAMES):
        path = prefix + ('' if name == 'release.json' else 'site/') + name
        result.append({'path': path, 'bytes': (metadata / name).stat().st_size, 'sha256': digest(metadata / name)})
    result.append({'path': prefix + 'site/.xonix-build.json', 'bytes': len(MARKER), 'sha256': hashlib.sha256(MARKER).hexdigest()})
    if 'sourceQualification' in release:
        qualification = metadata / 'source-qualification.json'
        if digest(qualification) != release['sourceQualification']['sha256'] or qualification.stat().st_size != release['sourceQualification']['bytes']:
            raise ValueError('Original source qualification bytes changed')
        proof = json.loads(qualification.read_bytes())
        if proof.get('format') == 'revealline-source-qualification.v2':
            validate_waived(proof, release, metadata)
        else:
            if any(key in proof for key in ('status', 'releaseEligible', 'testPolicy', 'waiverEvidence')) or (isinstance(proof.get('tests'), dict) and any(key in proof['tests'] for key in ('status', 'counts'))) or 'policyEvidence' in release['sourceQualification']:
                raise ValueError('Mixed v1/v2 qualification fields are ambiguous')
            if proof.get('format') != 'revealline-source-qualification.v1' or proof.get('version') != version or proof.get('sourceRevision') != release['sourceRevision'] or proof.get('actualCheckoutCommit') != release['sourceRevision'] or proof.get('sourceTree') != release['sourceTree'] or proof.get('actualCheckoutTree') != release['sourceTree'] or proof.get('passed') is not True or proof.get('allTrackedSourceContentsAndModesMatch') is not True:
                raise ValueError('Original source qualification identity changed')
            gates = proof.get('gates', [])
            if len(gates) != 6 or {gate.get('gate') for gate in gates} != {'test', 'lint', 'format', 'native-format', 'validate', 'motion-syntax'} or any(gate.get('step', {}).get('conclusion') != 'success' for gate in gates):
                raise ValueError('Original source qualification gates incomplete')
        result.append({'path': prefix + 'source-qualification.json', 'bytes': qualification.stat().st_size, 'sha256': digest(qualification)})
    return result


def locked_inputs(root=ROOT):
    lock = json.loads((root / 'source-lock.json').read_bytes())
    if lock['format'] != 'revealline-archive-originals.v2' or not lock['releases']:
        raise ValueError('Expected explicit original release cohorts')
    versions = [release['version'] for release in lock['releases']]
    if len(versions) != len(set(versions)):
        raise ValueError('Duplicate original release cohort')
    path = root / 'expected-inventory.json'
    if digest(path) != lock['expectedInventorySha256']:
        raise ValueError('Expected inventory pin changed')
    inventory = json.loads(path.read_bytes())
    validate_rows(inventory['files'])
    if len(inventory['files']) != lock['expectedFiles'] or sum(row['bytes'] for row in inventory['files']) != lock['expectedBytes'] or lock['budgetBytes'] != LIMIT:
        raise ValueError('Expected inventory size mismatch')
    derived = []
    for release in lock['releases']:
        derived.extend(metadata_inventory(root, release))
    derived.extend([
        {'path': '.nojekyll', 'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()},
        {'path': 'index.html', 'bytes': (root / 'index.html').stat().st_size, 'sha256': digest(root / 'index.html')},
        {'path': 'releases/index.html', 'bytes': (root / 'releases/index.html').stat().st_size, 'sha256': digest(root / 'releases/index.html')},
    ])
    if sorted(derived, key=lambda row: row['path']) != inventory['files']:
        raise ValueError('Canonical inventory differs from original metadata cohorts')
    return lock, inventory


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise ValueError('Usage: verify.py ARTIFACT')
    _, expected = locked_inputs()
    print(json.dumps(verify(Path(sys.argv[1]), expected['files'])))
