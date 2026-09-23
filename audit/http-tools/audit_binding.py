"""Read-only, fail-closed intake of the actual Archive58 initial-deployment receipts."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_ROOT = ROOT
INFRA = ROOT / 'repository'
REQUEST = ROOT / 'execution-request.reviewed.json'
BASE = 'https://mekhovov.github.io/revealline-archive-58/'
REPO = 'mekhovov/revealline-archive-58'
TREE = 'be7851a079bf66b1014731973c7a566113570776'
INVENTORY_SHA = 'a3ce3729deda536848233d7ea78cab1a1060b03b828f98d5853183bf2d8a9b7e'
LOCK_SHA = 'e770401e7c8cf18ce731b76ea360ba45fbc65e1c25b6c3724788c9752378b51c'
ROLES = {'main', 'commit', 'run', 'deployment', 'statuses', 'artifacts', 'receiptZIP'}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def local_bytes(path, limit=2 * 1024**2):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'Not an ordinary evidence file')
    require(path.stat().st_size <= limit, 'Evidence file exceeds bounded size')
    return path.read_bytes()


def original(pin):
    require(set(pin) == {'path', 'bytes', 'sha256'}, 'Invalid evidence descriptor')
    name = pin['path']
    require(isinstance(name, str) and name and not Path(name).is_absolute(), 'Evidence path must be relative')
    require(not re.search(r'[\\\x00-\x1f]', name) and all(p not in ['', '.', '..'] for p in name.split('/')), 'Unsafe evidence path')
    path = AUTHORITY_ROOT
    for part in name.split('/'):
        path = path / part
        require(not path.is_symlink(), 'Symlink evidence path')
    raw = local_bytes(path)
    require(type(pin['bytes']) is int and len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'Evidence pin changed: ' + name)
    return raw


def git(*args):
    return subprocess.check_output(['git', '-C', str(INFRA), *args], env={**os.environ, 'GIT_NO_LAZY_FETCH': '1'})


def candidate_inventory():
    raw = local_bytes(ROOT / 'inputs/expected-inventory.json')
    lock_raw = local_bytes(ROOT / 'inputs/source-lock.json')
    require(sha(raw) == INVENTORY_SHA and sha(lock_raw) == LOCK_SHA, 'Prepared input pin changed')
    value, lock = json.loads(raw), json.loads(lock_raw)
    require(set(value) == {'base', 'files'} and value['base'] == BASE, 'Wrong inventory envelope')
    rows = value['files']; current = {r['path']: r for r in rows}
    require(len(rows) == len(current) == 1090 and sum(r['bytes'] for r in rows) == 590930993, 'Wrong finite inventory')
    # This is the initial archive: no predecessor or previously deployed rows exist.
    return raw, rows, lock


def validate_execution_binding():
    raw, rows, lock = candidate_inventory()
    request_raw = local_bytes(REQUEST, 32768)
    request = json.loads(request_raw)
    require(set(request) == {'format', 'reviewed', 'archiveCommit', 'archiveTree', 'sourceCheckoutCommit', 'runId', 'deploymentId', 'deploymentStatusId', 'receiptArtifactId', 'pins'}, 'Unexpected execution request fields')
    require(request['format'] == 'revealline-archive58-http-request.v1' and request['reviewed'] is True, 'Actual request requires explicit review')
    for key in ['archiveCommit', 'sourceCheckoutCommit']:
        require(isinstance(request[key], str) and re.fullmatch('[a-f0-9]{40}', request[key]), 'Actual commit required: ' + key)
    require(request['archiveTree'] == TREE, 'Unreviewed successor tree')
    require(request['sourceCheckoutCommit'] == request['archiveCommit'], 'Held checkout must be the actual deployed merge')
    for key in ['runId', 'deploymentId', 'deploymentStatusId', 'receiptArtifactId']:
        require(type(request[key]) is int and request[key] > 0, 'Actual positive identity required: ' + key)
    require(set(request['pins']) == ROLES, 'Complete original authority and receipt pins required')
    bodies = {key: original(pin) for key, pin in request['pins'].items()}
    values = {key: json.loads(body) for key, body in bodies.items() if key != 'receiptZIP'}
    commit = request['archiveCommit']; run_id = request['runId']; dep_id = request['deploymentId']
    api = 'https://api.github.com/repos/' + REPO
    require(values['main']['object']['sha'] == commit and values['main']['ref'] == 'refs/heads/main', 'Main does not name successor')
    c = values['commit']
    require(c['sha'] == commit and c['tree']['sha'] == TREE and c['url'] == api + '/git/commits/' + commit, 'Commit/tree original mismatch')
    run = values['run']
    require(run['id'] == run_id and run['head_sha'] == commit and run['head_branch'] == 'main' and run['status'] == 'completed' and run['conclusion'] == 'success', 'Run is not the completed successful successor')
    require(run['repository']['full_name'] == REPO and run['path'] == '.github/workflows/deploy.yml', 'Wrong run repository/workflow')
    dep = values['deployment']
    require(dep['id'] == dep_id and dep['sha'] == commit and dep['ref'] == 'main' and dep['environment'] == 'github-pages' and dep['repository_url'] == api, 'Wrong deployment')
    statuses = values['statuses']; require(isinstance(statuses, list) and statuses, 'Missing deployment statuses')
    status = max(statuses, key=lambda item: item['id'])
    require(status['id'] == request['deploymentStatusId'] and status['state'] == 'success' and status['environment_url'] == BASE and status['deployment_url'] == api + '/deployments/' + str(dep_id), 'Latest deployment status is not this successful site')
    require(status['log_url'].startswith('https://github.com/' + REPO + '/actions/runs/' + str(run_id) + '/'), 'Status is not linked to the actual run')
    matches = [a for a in values['artifacts']['artifacts'] if a['id'] == request['receiptArtifactId']]
    require(len(matches) == 1, 'Receipt artifact identity missing/duplicated')
    artifact = matches[0]; zip_raw = bodies['receiptZIP']
    require(artifact['name'] == 'archive58-verification-receipts' and artifact['expired'] is False and artifact['workflow_run']['id'] == run_id and artifact['workflow_run']['head_sha'] == commit, 'Wrong receipt artifact run')
    require(artifact['size_in_bytes'] == len(zip_raw) and artifact['digest'] == 'sha256:' + sha(zip_raw), 'Original receipt ZIP digest differs')
    require(git('rev-parse', 'HEAD').decode().strip() == request['sourceCheckoutCommit'] and git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE, 'Held source checkout changed')
    require(git('show', request['sourceCheckoutCommit'] + ':expected-inventory.json') == raw and local_bytes(INFRA / 'expected-inventory.json') == raw, 'Inventory not from held exact source')
    require(git('show', request['sourceCheckoutCommit'] + ':source-lock.json') == local_bytes(ROOT / 'inputs/source-lock.json'), 'Source-lock differs from reviewed source')
    with zipfile.ZipFile(io.BytesIO(zip_raw)) as archive:
        names = ['receipt.json', 'expected-inventory.json', 'zip-receipt-v0.89.0.json']
        require(sorted(archive.namelist()) == sorted(names), 'Receipt ZIP has unexpected/duplicate members')
        require(sum(i.file_size for i in archive.infolist()) <= 1024**2 and all(i.file_size <= 512*1024 for i in archive.infolist()), 'Receipt members exceed bounds')
        require(archive.testzip() is None and archive.read('expected-inventory.json') == raw, 'Hosted receipt inventory differs')
        receipt = json.loads(archive.read('receipt.json'))
        require(receipt['status'] == 'PASS' and receipt['files'] == 1090 and receipt['bytes'] == 590930993 and receipt['archiveId'] == 'archive-58' and receipt['archiveCommit'] == commit and receipt['archiveTree'] == TREE and receipt['expectedInventorySha256'] == INVENTORY_SHA and receipt['noHistoricalBuilds'] is True, 'Hosted complete-inventory receipt differs')
        require(receipt['toolingCommit'] == lock['toolingCommit'] and len(receipt['releases']) == 1, 'Hosted source cohort differs')
        for expected in lock['releases']:
            versions = [r for r in receipt['releases'] if r['version'] == expected['version']]
            require(len(versions) == 1, 'Wrong receipt edition')
            release = versions[0]; extraction = json.loads(archive.read('zip-receipt-' + expected['version'] + '.json'))
            require(release['sourceRevision'] == expected['sourceRevision'] and release['tagObject'] == expected['tagObject'] and release['originalZipExtraction'] == extraction, 'Original source/tag/extraction differs')
            require(extraction['distributionSha256'] == expected['distributionSha256'] and extraction['manifestSha256'] == expected['metadata']['manifest.json'] and extraction['gameSourceRevision'] == expected['sourceRevision'] and extraction['version'] == expected['version'] and extraction['crcAndHashesVerified'] is True, 'Original ZIP verification differs')
    return {'request': request, 'requestRaw': request_raw, 'requestSha256': sha(request_raw), 'raw': raw, 'rows': rows, 'receipt': receipt, 'evidenceBodies': bodies}

