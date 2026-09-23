"""Narrow archive mirror of the reviewed main Pages v2 waiver consumer.

Does not turn waived tests into passing tests. The archive preparer separately
compares the pinned policy original to the exact frozen source before and after
extraction; this module verifies the schema and original metadata byte pins.
"""
import hashlib
import json
import re

GATES = ('validate', 'lint', 'format', 'native-format', 'motion-syntax')
COMMANDS = ('npm run validate', 'npm run lint', 'npm run format:check',
            'npm run format:native:check', 'node --check authoring/motion-lab/app.js')
FORBIDDEN = ('passed', 'testFiles', 'testShards', 'shards', 'additionalManualQualification')
POLICY_PATH = 'publishing/test-policy.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def positive(value, maximum):
    return type(value) is int and 0 < value <= maximum


def safe_path(value):
    return (isinstance(value, str) and len(value) <= 1024 and
            not re.search(r'[\\\x00-\x1f\x7f:%?#]', value) and
            all(part not in ('', '.', '..') for part in value.split('/')))


def generic_pin(pin):
    return (exact(pin, ('path', 'bytes', 'sha256')) and safe_path(pin['path']) and
            type(pin['bytes']) is int and 0 <= pin['bytes'] <= 64 * 1024**2 and
            isinstance(pin['sha256'], str) and re.fullmatch('[a-f0-9]{64}', pin['sha256']))


def bounded_pin(pin, maximum):
    return generic_pin(pin) and positive(pin['bytes'], maximum)


def successful_step(row):
    step = row.get('step') if isinstance(row, dict) else None
    return isinstance(step, dict) and step.get('status') == 'completed' and step.get('conclusion') == 'success'


def policy_original(metadata, release):
    pin = release.get('sourceQualification', {}).get('policyEvidence')
    require(bounded_pin(pin, 16 * 1024) and pin['path'] == POLICY_PATH,
            'Waived qualification requires bounded exact-source policy pin')
    file = metadata / 'test-policy.json'
    require(not file.is_symlink() and file.is_file() and file.stat().st_size == pin['bytes'],
            'Invalid original policy file')
    raw = file.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == pin['sha256'], 'Original policy byte pin changed')
    return raw


def validate_waived(proof, release, metadata):
    require(isinstance(proof, dict) and proof.get('format') == 'revealline-source-qualification.v2' and
            proof.get('status') == 'qualified-with-test-waiver' and proof.get('releaseEligible') is True and
            proof.get('version') == release['version'] and proof.get('sourceRevision') == release['sourceRevision'] and
            isinstance(proof.get('sourceTree'), str) and re.fullmatch('[a-f0-9]{40}', proof['sourceTree']) and
            proof['sourceTree'] == release['sourceTree'] and
            proof.get('actualCheckoutCommit') == proof['sourceRevision'] and
            proof.get('actualCheckoutTree') == proof['sourceTree'] and
            proof.get('allTrackedSourceContentsAndModesMatch') is True and
            not any(key in proof for key in FORBIDDEN) and
            exact(proof.get('tests'), ('status', 'counts')) and
            proof['tests']['status'] == 'waived' and proof['tests']['counts'] is None,
            'Waived source qualification identity or result mismatch')
    gates = proof.get('gates')
    require(isinstance(gates, list) and len(gates) == len(GATES), 'Waived source qualification gates incomplete')
    for row, gate, command in zip(gates, GATES, COMMANDS):
        require(isinstance(row, dict) and row.get('gate') == gate and row.get('command') == command and
                positive(row.get('jobId'), 10**14) and 'actualJobSteps' not in row and successful_step(row) and
                isinstance(row['step'].get('name'), str) and bool(row['step']['name']) and
                positive(row['step'].get('number'), 10000), 'Waived source qualification gate mismatch')
    policy = proof.get('testPolicy')
    require(exact(policy, ('mode', 'authorization', 'reason', 'policyEvidence')) and
            policy['mode'] == 'waived' and policy['authorization'] == 'explicit-user-request-20260922' and
            isinstance(policy['reason'], str) and bool(policy['reason'].strip()) and len(policy['reason']) <= 2000,
            'Waived qualification requires explicit user policy')
    pin = policy['policyEvidence']
    require(bounded_pin(pin, 16 * 1024) and pin['path'] == POLICY_PATH and
            pin == release['sourceQualification'].get('policyEvidence'), 'Waived policy evidence pin differs')
    waiver, pins = proof.get('waiverEvidence'), proof.get('evidencePins')
    require(exact(waiver, ('runId', 'runEvidence', 'jobsEvidence')) and positive(waiver['runId'], 10**14) and
            bounded_pin(waiver['runEvidence'], 4 * 1024**2) and bounded_pin(waiver['jobsEvidence'], 4 * 1024**2) and
            isinstance(pins, list) and 3 <= len(pins) <= 2000 and all(generic_pin(item) for item in pins) and
            len({item['path'] for item in pins}) == len(pins) and
            all(wanted in pins for wanted in (pin, waiver['runEvidence'], waiver['jobsEvidence'])),
            'Waived qualification evidence pins incomplete')
    build, frozen = proof.get('ordinaryBuildCorroboration'), proof.get('frozenArtifactCorroboration')
    require(isinstance(build, dict) and build.get('command') == 'npm run build' and successful_step(build) and
            isinstance(frozen, dict) and positive(frozen.get('artifactId'), 10**14) and
            ('runId' not in frozen or frozen['runId'] == waiver['runId']) and
            all(frozen.get(key) is True for key in (
                'wholeOriginalArtifactVerifiedBeforeQualification', 'sourceTarGitBlobTypeModeAndPaxCommitVerified',
                'allInnerZipManifestBytesVerified', 'frozenOfflineInventoryAndBindingsVerified')),
            'Waived qualification build/frozen proof incomplete')
    original = json.loads(policy_original(metadata, release).decode('utf-8'))
    require(exact(original, ('format', 'mode', 'authorization', 'scope', 'reason', 'restoration')) and
            original['format'] == 'revealline-release-test-policy.v1' and original['mode'] == 'waived' and
            original['authorization'] == 'explicit-user-request-20260922' and original['scope'] == 'automated-test-suites' and
            original['reason'] == policy['reason'] and isinstance(original['restoration'], str) and
            bool(original['restoration'].strip()) and len(original['restoration']) <= 2000,
            'Waived source qualification policy invalid')
