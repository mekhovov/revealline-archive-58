#!/usr/bin/env python3
"""Configure dedicated archive-58 inventory from v0.89.0's original metadata."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "v0.89.0"
SOURCE = "9374f7fab315a2b9145d699cb4548fb7807b1380"
TREE = "d4338abbf5c65809af38a398cedf0d9fcae86b7f"
TAG = "08e1aeb0aa8b0a02e3ac535f00f62dc907bdf9f3"
ZIP = "afabe1075b6c2bbdc9c1aae98ffbfa462a8a3f1b2478ae36aeac65d60afac622"
ZIP_BYTES = 591098295
TOOLING = "30530b3436a1a9737be93f67f308587f89b2f8bc"
EXTRACTOR = "38081b1791b49cb7328d18b4d4325c2876bb3bc8d7db03f4610f8d8a7c4bf91b"

def sha(data): return hashlib.sha256(data).hexdigest()
def json_bytes(value): return (json.dumps(value, indent=2) + "\n").encode()

def main():
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    import verify
    metadata = ROOT / "metadata" / VERSION
    record = json.loads((metadata / "release.json").read_bytes())
    manifest = json.loads((metadata / "manifest.json").read_bytes())
    checksum = (metadata / "distribution.zip.sha256").read_bytes()
    qualification = metadata / "source-qualification.json"
    policy = metadata / "test-policy.json"
    assert qualification.stat().st_size == 14169 and sha(qualification.read_bytes()) == "e2a149840ab107913873c562d4486bb81877427aa9fd1ad5776541b0355eb373"
    assert policy.stat().st_size == 490 and sha(policy.read_bytes()) == "b6887ba7f2b84a007b96de14fc867ac38ac8135d7c231c7ade7ebc52ba31704a"
    assert record["version"] == manifest["version"] == VERSION
    assert record["sourceRevision"] == manifest["sourceRevision"] == SOURCE
    assert record["distributionSha256"] == ZIP == checksum.decode().split()[0]
    release = {
        "version": VERSION, "sourceRevision": SOURCE, "sourceTree": TREE, "tagObject": TAG,
        "distributionSha256": ZIP, "distributionBytes": ZIP_BYTES,
        "metadata": {name: sha((metadata / name).read_bytes()) for name in ("release.json", "manifest.json", "distribution.zip.sha256")},
        "sourceQualification": {
            "bytes": qualification.stat().st_size, "sha256": sha(qualification.read_bytes()),
            "policyEvidence": {"path": "publishing/test-policy.json", "bytes": policy.stat().st_size, "sha256": sha(policy.read_bytes())},
        },
    }
    lock = {
        "format": "revealline-archive-originals.v2", "archiveId": "archive-58", "repository": "mekhovov/revealline-archive-58",
        "sourceRepository": "mekhovov/revealline", "toolingCommit": TOOLING,
        "extractorPath": "publishing/pages-controller/extract-current.py", "extractorSha256": EXTRACTOR,
        "budgetBytes": 800000000, "releases": [release],
    }
    (ROOT / "source-lock.json").write_bytes(json_bytes(lock))
    rows = verify.metadata_inventory(ROOT, release)
    rows.extend([
        {"path": ".nojekyll", "bytes": 0, "sha256": sha(b"")},
        {"path": "index.html", "bytes": (ROOT / "index.html").stat().st_size, "sha256": sha((ROOT / "index.html").read_bytes())},
        {"path": "releases/index.html", "bytes": (ROOT / "releases/index.html").stat().st_size, "sha256": sha((ROOT / "releases/index.html").read_bytes())},
    ])
    rows.sort(key=lambda row: row["path"])
    inventory = {"base": "https://mekhovov.github.io/revealline-archive-58/", "files": rows}
    inventory_bytes = json_bytes(inventory)
    (ROOT / "expected-inventory.json").write_bytes(inventory_bytes)
    lock.update({"expectedInventorySha256": sha(inventory_bytes), "expectedFiles": len(rows), "expectedBytes": sum(row["bytes"] for row in rows)})
    (ROOT / "source-lock.json").write_bytes(json_bytes(lock))
    original = json.loads((ROOT / "authority/release-original.json").read_bytes())
    assert original["id"] == 394259144 and original["tag_name"] == VERSION
    assert not original["draft"] and not original["prerelease"]
    assert len(original["assets"]) == 9 and all(a["state"] == "uploaded" and a["digest"].startswith("sha256:") for a in original["assets"])
    assets = [{"id": a["id"], "name": a["name"], "bytes": a["size"], "sha256": a["digest"].removeprefix("sha256:")} for a in original["assets"]]
    assert next(a for a in assets if a["name"] == "distribution.zip")["sha256"] == ZIP
    assert next(a for a in assets if a["name"] == "distribution.zip")["bytes"] == ZIP_BYTES
    reviewed = json.loads((ROOT / "authority/reviewed-release-descriptors.json").read_bytes())
    assert len({a["name"] for a in assets}) == 9
    assert {a["name"]: (a["bytes"], a["sha256"]) for a in assets} == {a["name"]: (a["bytes"], a["sha256"]) for a in reviewed["artifacts"]}
    tag = json.loads((ROOT / "authority/tag-original.json").read_bytes())
    ref = json.loads((ROOT / "authority/tag-ref-original.json").read_bytes())
    assert tag["sha"] == ref["object"]["sha"] == TAG and tag["object"]["sha"] == SOURCE and tag["object"]["type"] == "commit"
    (ROOT / "input-authority.json").write_bytes(json_bytes({
        "version": VERSION, "releaseId": 394259144, "source": SOURCE, "tree": TREE, "tagObject": TAG,
        "donorCommit": "de23f0600a8410d0060f2bbcc1887bfb37d049a0", "toolingCommit": TOOLING, "donorDeploymentMerge": "de23f0600a8410d0060f2bbcc1887bfb37d049a0", "priorAcceptedPaths": 0,
        "mainPublisherRun": None, "archivePublicAcceptance": False,
        "releaseUrl": original["html_url"], "publishedAt": original["published_at"],
        "originalAssets": assets,
        "authorityFiles": {p.name: sha(p.read_bytes()) for p in sorted((ROOT / "authority").glob("*.json"))},
    }))

if __name__ == "__main__": main()
