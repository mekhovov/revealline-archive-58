"""Preserve selected original GitHub Release ZIPs as one immutable archive."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from verify import ROOT, digest, locked_inputs, verify
from qualification_v2 import POLICY_PATH, policy_original

MIN_FREE_BYTES = 3 * 1024**3


def run(args):
    return subprocess.check_output(args, text=True).strip()


def verify_source(source, lock, root=ROOT):
    git = ['git', '-C', str(source)]
    if run([*git, 'rev-parse', 'HEAD']) != lock['toolingCommit'] or run([*git, 'status', '--porcelain', '--untracked-files=no']):
        raise ValueError('Tooling must equal the clean reviewed source commit')
    for release in lock['releases']:
        ref = 'refs/tags/' + release['version']
        if run([*git, 'rev-parse', ref]) != release['tagObject'] or run([*git, 'rev-parse', ref + '^{commit}']) != release['sourceRevision']:
            raise ValueError('Original release tag/source identity changed')
        if 'policyEvidence' in release.get('sourceQualification', {}):
            if run([*git, 'rev-parse', ref + '^{tree}']) != release['sourceTree']:
                raise ValueError('Waived source qualification tree changed')
            original = policy_original(root / 'metadata' / release['version'], release)
            committed = subprocess.check_output([*git, 'show', release['sourceRevision'] + ':' + POLICY_PATH])
            if original != committed:
                raise ValueError('Waiver policy differs from exact frozen source')
    extractor = source / lock['extractorPath']
    if digest(extractor) != lock['extractorSha256']:
        raise ValueError('Reviewed extractor bytes changed')
    return extractor


def prepare(source, output, root=ROOT):
    source = source.resolve()
    output = output.absolute()
    # Fail before creating output or fetching any ZIP. Tiny unit fixtures mock
    # only this capacity observation; the command line offers no guard bypass.
    if shutil.disk_usage(output.parent).free < MIN_FREE_BYTES:
        raise ValueError('Original ZIP preparation requires at least 3 GiB free')
    lock, inventory = locked_inputs(root)
    extractor = verify_source(source, lock, root)
    # A fresh CI workspace owns every output. Existing artifacts are never replaced.
    output.mkdir(parents=True, exist_ok=False)
    artifact = output / 'artifact'
    extractions = []
    for cohort in lock['releases']:
        version = cohort['version']
        metadata = root / 'metadata' / version
        release = artifact / 'releases' / version
        release.mkdir(parents=True)
        receipt = output / ('zip-receipt-' + version + '.json')
        # The pinned extractor deletes each temporary ZIP before the next cohort.
        subprocess.run([sys.executable, str(extractor), '--metadata', str(metadata), '--output', str(release / 'site'), '--receipt', str(receipt)], check=True)
        extraction = json.loads(receipt.read_bytes())
        if extraction['version'] != version or extraction['gameSourceRevision'] != cohort['sourceRevision'] or extraction['distributionSha256'] != cohort['distributionSha256'] or extraction['manifestSha256'] != cohort['metadata']['manifest.json'] or extraction['crcAndHashesVerified'] is not True:
            raise ValueError('Original ZIP extraction receipt identity changed')
        shutil.copyfile(metadata / 'release.json', release / 'release.json')
        if 'sourceQualification' in cohort:
            shutil.copyfile(metadata / 'source-qualification.json', release / 'source-qualification.json')
        extractions.append({'version': version, 'sourceRevision': cohort['sourceRevision'], 'tagObject': cohort['tagObject'], 'originalZipExtraction': extraction})
    shutil.copyfile(root / 'index.html', artifact / 'index.html')
    shutil.copyfile(root / 'releases/index.html', artifact / 'releases/index.html')
    (artifact / '.nojekyll').write_bytes(b'')
    result = verify(artifact, inventory['files'])
    verify_source(source, lock, root)
    if locked_inputs(root) != (lock, inventory):
        raise ValueError('Archive inputs changed during extraction')
    result.update({'archiveId': lock['archiveId'], 'releases': extractions, 'toolingCommit': lock['toolingCommit'], 'archiveCommit': run(['git', '-C', str(root), 'rev-parse', 'HEAD']), 'archiveTree': run(['git', '-C', str(root), 'rev-parse', 'HEAD^{tree}']), 'expectedInventorySha256': lock['expectedInventorySha256'], 'noHistoricalBuilds': True})
    with (output / 'receipt.json').open('x') as target:
        json.dump(result, target, indent=2)
        target.write('\n')
    shutil.copyfile(root / 'expected-inventory.json', output / 'expected-inventory.json')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = prepare(args.source, args.out)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
