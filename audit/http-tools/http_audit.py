"""Read every hash-pinned Archive58 HTTP body without persisting payloads.

Adapted from the Archive03 auditor. Public execution requires an explicit --run;
there is no URL, inventory, or output-path override. Tests use an injected local
in-memory transport and never contact the public site.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import quote
import uuid

from audit_binding import validate_execution_binding, candidate_inventory

BASE_DIR = Path(__file__).resolve().parents[1]
BASE = 'https://mekhovov.github.io/revealline-archive-58/'
COMMIT = None
BINDING = None
INVENTORY_SHA = 'a3ce3729deda536848233d7ea78cab1a1060b03b828f98d5853183bf2d8a9b7e'
EXPECTED_FILES = 1090
EXPECTED_BYTES = 590930993
SOCKET_TIMEOUT = 25
ATTEMPT_SECONDS = 90
AUDIT_SECONDS = 1800
MAX_ATTEMPTS = 3
CHUNK_BYTES = 65536
MIMES = {
    '.html': {'text/html'},
    '.mjs': {'text/javascript', 'application/javascript'},
    '.js': {'text/javascript', 'application/javascript'},
    '.css': {'text/css'},
    '.json': {'application/json'},
    '.webmanifest': {'application/manifest+json', 'application/json'},
    '.png': {'image/png'},
    '.jpg': {'image/jpeg'},
    '.svg': {'image/svg+xml'},
    '.woff2': {'font/woff2'},
    '.ttf': {'font/ttf', 'application/x-font-ttf', 'application/font-sfnt'},
    '.txt': {'text/plain'},
    '.md': {'text/plain', 'text/markdown', 'text/x-markdown', 'application/octet-stream'},
    '.pb': {'application/octet-stream', 'text/plain'},
    '.rlmedia': {'application/octet-stream'},
    '.rlstory': {'application/octet-stream'},
    '.sha256': {'application/octet-stream', 'text/plain'},
    '': {'application/octet-stream', 'text/plain'},
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_row(row):
    if set(row) != {'path', 'bytes', 'sha256'}:
        raise ValueError('Unexpected inventory descriptor fields')
    name = row['path']
    if not isinstance(name, str) or not name or len(name) > 1024:
        raise ValueError('Invalid inventory path')
    if (PurePosixPath(name).is_absolute() or
            re.search(r'[\\\x00-\x1f\x7f:%?#]', name) or
            any(part in ['', '.', '..'] for part in name.split('/'))):
        raise ValueError('Unsafe inventory path')
    if type(row['bytes']) is not int or not 0 <= row['bytes'] <= EXPECTED_BYTES:
        raise ValueError('Invalid inventory byte count')
    if not isinstance(row['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', row['sha256']):
        raise ValueError('Invalid inventory SHA-256')
    if PurePosixPath(name).suffix.lower() not in MIMES:
        raise ValueError('No reviewed MIME policy for ' + name)
    return row


def pinned_inventory():
    global COMMIT, BINDING
    binding = validate_execution_binding()
    raw, rows = binding['raw'], [validate_row(row) for row in binding['rows']]
    COMMIT = binding['request']['archiveCommit']
    BINDING = binding
    return raw, rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never follow a response to any unreviewed destination, even another
        # path on the same host. This audit requires exact canonical final URLs.
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect refused', headers, fp)


def fetch_once(row, attempt, opener, *, deadline, clock=time.monotonic):
    validate_row(row)
    url = BASE + quote(row['path'], safe='/')
    result = {
        'path': row['path'], 'url': url, 'attempt': attempt,
        'expectedBytes': row['bytes'], 'expectedSha256': row['sha256'],
        'at': now(), 'requestStarted': False, 'bytes': 0,
    }
    started = clock()
    attempt_deadline = min(deadline, started + ATTEMPT_SECONDS)
    try:
        if started >= deadline:
            raise TimeoutError('Audit deadline reached before request')
        request = urllib.request.Request(url, headers={
            'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache',
            'User-Agent': 'RevealLine-archive58-byte-audit/2.0',
        })
        result['requestStarted'] = True
        with opener.open(request, timeout=min(SOCKET_TIMEOUT, max(0.1, attempt_deadline - started))) as response:
            result.update({
                'statusCode': response.status, 'finalURL': response.geturl(),
                'contentType': response.headers.get('Content-Type', ''),
                'contentEncoding': response.headers.get('Content-Encoding', 'identity'),
                'contentLength': response.headers.get('Content-Length'),
            })
            if response.status != 200 or response.geturl() != url:
                raise ValueError('HTTP status/final URL mismatch')
            if result['contentEncoding'].strip().lower() not in ['', 'identity']:
                raise ValueError('Unexpected content encoding')
            declared = result['contentLength']
            if declared is not None and (not re.fullmatch(r'\d+', declared.strip()) or int(declared) != row['bytes']):
                raise ValueError('Content-Length differs from pinned body size')
            actual = hashlib.sha256()
            read_body = getattr(response, 'read1', None)
            result['bodyReadMethod'] = 'read1' if callable(read_body) else 'read'
            if not callable(read_body):
                read_body = response.read
            while True:
                if clock() >= attempt_deadline:
                    raise TimeoutError('HTTP body deadline exceeded')
                # Read no more than one byte beyond the pin, including empty files.
                # HTTPResponse.read1 avoids read(n)'s accumulation loop. A
                # blocking transport operation can still overrun the deadline;
                # never accept its result, including delayed EOF, afterward.
                block = read_body(min(CHUNK_BYTES, row['bytes'] - result['bytes'] + 1))
                if block:
                    result['bytes'] += len(block)
                    if result['bytes'] > row['bytes']:
                        raise ValueError('Body exceeds pinned size')
                    actual.update(block)
                if clock() >= attempt_deadline:
                    raise TimeoutError('HTTP body deadline exceeded after read')
                if not block:
                    break
            result['sha256'] = actual.hexdigest()
            if result['bytes'] != row['bytes'] or result['sha256'] != row['sha256']:
                raise ValueError('Body size/SHA-256 mismatch')
            suffix = PurePosixPath(row['path']).suffix.lower()
            if result['contentType'].split(';', 1)[0].strip().lower() not in MIMES[suffix]:
                raise ValueError('Unexpected MIME for ' + (suffix or row['path']))
            result['status'] = 'PASS'
    except Exception as error:
        result['status'] = 'FAIL'
        result['errorType'] = type(error).__name__
        result['error'] = str(error)
        if isinstance(error, urllib.error.HTTPError):
            result['statusCode'] = error.code
            error.close()
    finished = clock()
    if result.get('status') == 'PASS' and finished >= attempt_deadline:
        result.update(status='FAIL', errorType='TimeoutError', error='HTTP verification completed after deadline')
    result['elapsedSeconds'] = round(finished - started, 3)
    return result


def check_row(row, opener, record_attempt, *, deadline, clock=time.monotonic, sleep=time.sleep):
    final = None
    for number in range(1, MAX_ATTEMPTS + 1):
        final = fetch_once(row, number, opener, deadline=deadline, clock=clock)
        # Persist every attempt as it happens, including unsuccessful retries.
        record_attempt(final)
        if final['status'] == 'PASS' or clock() >= deadline:
            break
        if number < MAX_ATTEMPTS:
            sleep(min(number, max(0, deadline - clock())))
    return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='Audit the fixed public Archive58 inventory')
    parser.add_argument('--workers', type=int, choices=[4], default=4)
    parser.add_argument('--prepare', action='store_true', help='Check local candidate only; no authority or public requests')
    args = parser.parse_args()
    if args.prepare:
        if args.run:
            parser.error('--prepare cannot authorize --run')
        raw, rows, _ = candidate_inventory()
        for row in rows:
            validate_row(row)
        print(json.dumps({'status': 'PREPARED_ACTUAL_BINDING_REQUIRED', 'files': len(rows), 'bytes': EXPECTED_BYTES, 'preservedCanonicalRows': 0, 'networkRequests': 0}))
        return 0
    raw, rows = pinned_inventory()
    if not args.run:
        print(json.dumps({'status': 'READY', 'base': BASE, 'files': len(rows), 'bytes': EXPECTED_BYTES,
                          'inventorySha256': INVENTORY_SHA, 'networkRequests': 0}))
        return 0
    if shutil.disk_usage(BASE_DIR).free < 1024**3:
        raise ValueError('At least 1 GiB local free space required')
    out = BASE_DIR / 'http' / ('http-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    out.parent.mkdir(exist_ok=True)
    out.mkdir(exist_ok=False)
    (out / 'expected-inventory.json').write_bytes(raw)
    (out / 'auditor.py').write_bytes(Path(__file__).read_bytes())
    (out / 'audit_binding.py').write_bytes(Path(__file__).with_name('audit_binding.py').read_bytes())
    (out / 'execution-request.json').write_bytes(BINDING['requestRaw'])
    (out / 'authority-originals').mkdir()
    for role, body in BINDING['evidenceBodies'].items():
        extension = '.zip' if role == 'receiptZIP' else '.json'
        (out / 'authority-originals' / (role + extension)).write_bytes(body)
    admitted_binding = BINDING
    deadline = time.monotonic() + AUDIT_SECONDS
    started = now()
    finished = []
    trial_count = 0
    attempt_failures = 0
    write_lock = threading.Lock()
    with (out / 'http-results.jsonl').open('x') as results, (out / 'http-attempts.jsonl').open('x') as attempts:
        def record_attempt(result):
            nonlocal trial_count, attempt_failures
            with write_lock:
                attempts.write(json.dumps(result) + '\n')
                attempts.flush()
                trial_count += 1
                attempt_failures += result['status'] != 'PASS'

        def worker(row):
            opener = urllib.request.build_opener(NoRedirect())
            return check_row(row, opener, record_attempt, deadline=deadline)

        print(json.dumps({'status': 'RUNNING', 'directory': str(out), 'files': len(rows), 'workers': args.workers}), flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(worker, row) for row in rows]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                finished.append(result)
                results.write(json.dumps(result) + '\n')
                results.flush()
                if len(finished) % 25 == 0:
                    print(json.dumps({'checked': len(finished), 'total': len(rows),
                                      'failed': sum(row['status'] != 'PASS' for row in finished)}), flush=True)
    if len(finished) != len(rows) or {row['path'] for row in finished} != {row['path'] for row in rows}:
        raise AssertionError('Audit result inventory is incomplete')
    failed = [row for row in finished if row['status'] != 'PASS']
    unrequested = [row['path'] for row in finished if not row['requestStarted']]
    unchanged_authority = False
    authority_error = None
    try:
        final_binding = validate_execution_binding()
        unchanged_authority = final_binding['requestSha256'] == admitted_binding['requestSha256']
        if not unchanged_authority:
            authority_error = 'Execution request changed during audit'
    except Exception as error:
        authority_error = str(error)
    audit_deadline_exceeded = time.monotonic() >= deadline
    report = {
        'status': 'FAIL' if failed or not unchanged_authority or audit_deadline_exceeded else 'PASS', 'base': BASE, 'archiveCommit': COMMIT,
        'files': len(finished), 'expectedBytes': EXPECTED_BYTES,
        'verifiedBytes': sum(row['bytes'] for row in finished if row['status'] == 'PASS'),
        'failedFiles': len(failed), 'failures': failed, 'skipped': unrequested,
        'expectedInventorySha256': INVENTORY_SHA, 'startedAt': started, 'verifiedAt': now(),
        'attempts': trial_count, 'failedAttempts': attempt_failures,
        'retriedFiles': sum(row['attempt'] > 1 for row in finished), 'workers': args.workers,
        'socketTimeoutSeconds': SOCKET_TIMEOUT, 'attemptDeadlineSeconds': ATTEMPT_SECONDS,
        'auditDeadlineSeconds': AUDIT_SECONDS, 'maxAttemptsPerFile': MAX_ATTEMPTS,
        'auditDeadlineExceeded': audit_deadline_exceeded,
        'deadlineSemantics': 'Acceptance checked before/after body reads and after response close and final authority validation; expired completions fail. A blocking transport operation may overrun; socket timeout is inactivity, not a strict process wall limit.',
        'allFinalURLsExact': all(row.get('finalURL') == row['url'] for row in finished),
        'payloadFilesPersisted': False,
        'sourcePinsUnchanged': unchanged_authority, 'authorityError': authority_error,
        'archiveTree': admitted_binding['request']['archiveTree'],
        'sourceCheckoutCommit': admitted_binding['request']['sourceCheckoutCommit'],
        'runId': admitted_binding['request']['runId'],
        'deploymentId': admitted_binding['request']['deploymentId'],
        'deploymentStatusId': admitted_binding['request']['deploymentStatusId'],
        'receiptArtifactId': admitted_binding['request']['receiptArtifactId'],
        'executionRequestSha256': admitted_binding['requestSha256'],
        'preservedOldCanonicalRows': 0,
        'scope': 'Every pinned canonical HTTP body and explicit MIME, including hidden metadata. Independent of browser/offline or physical-device acceptance.',
    }
    with (out / 'http-report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'directory': str(out), 'report': report}), flush=True)
    return 1 if report['status'] != 'PASS' else 0


if __name__ == '__main__':
    raise SystemExit(main())

