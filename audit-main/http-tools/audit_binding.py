"""Fail-closed intake of the exact completed main Pages production receipts."""
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
INFRA = ROOT / 'repository'
REQUEST = ROOT / 'execution-request.reviewed.json'
BASE = 'https://mekhovov.github.io/revealline/'
REPO = 'mekhovov/revealline'
COMMIT = 'c2d4789f08fde3a50a7218bbc5c0d6a3b8997a4f'
TREE = '241e7666fa231c8bed926a929a9839a210dfa2b8'
SOURCE = 'c585bcd3220438da971e2927763b966f55ee8235'
SOURCE_TREE = '09de27014c17b338fd102e8ac3f300cdd8b88b9f'
INVENTORY_SHA = '508e283d1e6a626a70297ea989bd03253725e798d09691ed226df224cc99a9ed'
EXPECTED_FILES = 4034
EXPECTED_BYTES = 615951616
PRODUCTION_RUN = 35818574091
ROLES = {'main', 'commit', 'run', 'deployment', 'statuses', 'artifacts', 'receiptZIP'}

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def local_bytes(path, limit=2 * 1024**2):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'Not ordinary evidence')
    require(path.stat().st_size <= limit, 'Evidence exceeds bounded size')
    return path.read_bytes()

def original(pin):
    require(set(pin) == {'path', 'bytes', 'sha256'}, 'Invalid evidence pin')
    name = pin['path']
    require(isinstance(name, str) and name and not Path(name).is_absolute(), 'Relative evidence path required')
    require(not re.search(r'[\\\x00-\x1f]', name) and all(p not in ['', '.', '..'] for p in name.split('/')), 'Unsafe evidence path')
    path = ROOT
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
    require(sha(raw) == INVENTORY_SHA, 'Actual production inventory pin changed')
    value = json.loads(raw)
    require(set(value) == {'base', 'files'} and value['base'] == BASE, 'Wrong inventory envelope')
    rows = value['files']
    require(len(rows) == len({r['path'] for r in rows}) == EXPECTED_FILES and sum(r['bytes'] for r in rows) == EXPECTED_BYTES, 'Wrong finite inventory')
    return raw, rows, None

def validate_execution_binding():
    raw, rows, _ = candidate_inventory()
    request_raw = local_bytes(REQUEST, 32768)
    request = json.loads(request_raw)
    require(set(request) == {'format', 'reviewed', 'controllerCommit', 'controllerTree', 'sourceCheckoutCommit', 'runId', 'deploymentId', 'deploymentStatusId', 'receiptArtifactId', 'pins'}, 'Unexpected request fields')
    require(request['format'] == 'revealline-main-pages-http-request.v1' and request['reviewed'] is True, 'Explicit actual binding review required')
    require(request['controllerCommit'] == request['sourceCheckoutCommit'] == COMMIT and request['controllerTree'] == TREE, 'Wrong controller identity')
    for key in ['runId', 'deploymentId', 'deploymentStatusId', 'receiptArtifactId']:
        require(type(request[key]) is int and request[key] > 0, 'Actual positive identity required')
    require(request['runId'] == PRODUCTION_RUN and set(request['pins']) == ROLES, 'Wrong production run or incomplete authority')
    bodies = {key: original(pin) for key, pin in request['pins'].items()}
    values = {key: json.loads(body) for key, body in bodies.items() if key != 'receiptZIP'}
    api = 'https://api.github.com/repos/' + REPO
    require(values['main']['object']['sha'] == COMMIT and values['main']['ref'] == 'refs/heads/main', 'Main does not name deployed controller')
    c = values['commit']
    require(c['sha'] == COMMIT and c['tree']['sha'] == TREE and c['url'] == api + '/git/commits/' + COMMIT, 'Commit/tree mismatch')
    run = values['run']
    require(run['id'] == request['runId'] and run['head_sha'] == COMMIT and run['head_branch'] == 'main' and run['status'] == 'completed' and run['conclusion'] == 'success', 'Not successful actual production run')
    require(run['repository']['full_name'] == REPO and run['path'] == '.github/workflows/publish-frozen-pages.yml', 'Wrong run/workflow')
    dep = values['deployment']; dep_id = request['deploymentId']
    require(dep['id'] == dep_id and dep['sha'] == COMMIT and dep['ref'] == 'main' and dep['environment'] == 'github-pages' and dep['repository_url'] == api, 'Wrong deployment')
    statuses = values['statuses']; require(isinstance(statuses, list) and statuses, 'Missing deployment statuses')
    status = max(statuses, key=lambda item: item['id'])
    require(status['id'] == request['deploymentStatusId'] and status['state'] == 'success' and status['environment_url'] == BASE and status['deployment_url'] == api + '/deployments/' + str(dep_id), 'Wrong latest deployment status')
    require(status['log_url'].startswith('https://github.com/' + REPO + '/actions/runs/' + str(request['runId']) + '/'), 'Status not linked to actual production run')
    arts = values['artifacts']
    require(arts['total_count'] == len(arts['artifacts']), 'Incomplete artifact list')
    matches = [a for a in arts['artifacts'] if a['id'] == request['receiptArtifactId']]
    require(len(matches) == 1, 'Receipt artifact missing/duplicated')
    artifact = matches[0]; zip_raw = bodies['receiptZIP']
    require(artifact['name'] == 'frozen-pages-receipts' and artifact['expired'] is False and artifact['workflow_run']['id'] == request['runId'] and artifact['workflow_run']['head_sha'] == COMMIT, 'Wrong receipt artifact')
    require(artifact['size_in_bytes'] == len(zip_raw) and artifact['digest'] == 'sha256:' + sha(zip_raw), 'Receipt ZIP digest mismatch')
    require(git('rev-parse', 'HEAD').decode().strip() == COMMIT and git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE, 'Held deployed source changed')
    with zipfile.ZipFile(io.BytesIO(zip_raw)) as archive:
        require(sorted(archive.namelist()) == ['artifact-receipt.json', 'zip-receipt.json'], 'Unexpected receipt members')
        require(sum(i.file_size for i in archive.infolist()) <= 2*1024**2 and all(i.file_size <= 1024**2 for i in archive.infolist()), 'Receipt members exceed bounds')
        require(archive.testzip() is None, 'Corrupt receipt ZIP')
        receipt = json.loads(archive.read('artifact-receipt.json'))
        require(receipt['format'] == 'revealline-metadata-pages-artifact.v1' and receipt['controllerCommit'] == COMMIT and receipt['controllerTree'] == TREE and receipt['currentVersion'] == 'v0.90.0' and receipt['gameSourceRevision'] == SOURCE and receipt['qualifiedSourceTree'] == SOURCE_TREE, 'Wrong frozen receipt source/controller')
        require(receipt['publishable'] is True and receipt['browserAdmissionsRequired'] is True and receipt['admittedArchives'] == 58 and receipt['historicalBridges'] == 133, 'Receipt is not actual production eligible')
        require(receipt['files'] == rows and receipt['totalBytes'] == EXPECTED_BYTES and receipt['budgetBytes'] == 950000000, 'Public inventory differs from complete production receipt')
        for name, field in [('publication.json', 'configurationSha256'), ('catalog.json', 'catalogSha256')]:
            committed = git('show', COMMIT + ':publishing/pages-controller/' + name)
            require(sha(committed) == receipt[field] and local_bytes(INFRA / 'publishing/pages-controller' / name) == committed, 'Committed selector/catalog pin mismatch')
            if name == 'catalog.json':
                releases = json.loads(committed)['releases']
                require(len(releases) == 134 and len({row['version'] for row in releases}) == 134 and sum(row['version'] == 'v0.90.0' for row in releases) == 1, 'Wrong complete catalog coverage')
        extraction = json.loads(archive.read('zip-receipt.json'))
        require(extraction['version'] == 'v0.90.0' and extraction['gameSourceRevision'] == SOURCE and extraction['distributionSha256'] == '9014614f8fe0cb234460d859615b432c098487b21d9e9ae9446b943e35abbb87' and extraction['manifestSha256'] == '703e1b57ade676c9f136427647823f8487762277992757fa97fc4874de441618' and extraction['crcAndHashesVerified'] is True, 'Frozen ZIP source/hash identity mismatch')
    return {'request': request, 'requestRaw': request_raw, 'requestSha256': sha(request_raw), 'raw': raw, 'rows': rows, 'receipt': receipt, 'evidenceBodies': bodies}
