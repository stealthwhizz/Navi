"""Acceptance assertions for the disposable target started by ci_acceptance.py."""

import argparse
import json
import time
import urllib.request
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",default="http://127.0.0.1:8080")
    args = parser.parse_args()
    target = urlsplit(args.url)
    if target.scheme != "http" or target.hostname not in {"127.0.0.1", "localhost", "::1"} or target.username or target.password:
        raise SystemExit("The smoke test accepts a local HTTP dashboard only.")

    def request(path, method="GET", body=None):
        req = urllib.request.Request(args.url + path, method=method,
            data=json.dumps(body or {}).encode() if method == "POST" else None,
            headers={"Content-Type":"application/json","X-Navi":"local-scan"})
        with urllib.request.urlopen(req,timeout=15) as response:
            return json.load(response)

    assert request("/health")["database"] == "connected"
    previous = None
    for _ in range(2):
        scan_id = request("/api/scans","POST")["id"]
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            state = request("/api/state")
            if not state["running"]:
                assert not state["error"], state["error"]
                break
            time.sleep(.5)
        else:
            raise SystemExit("Scan did not finish within four minutes.")
        report = request(f"/api/scans/{scan_id}")
        assert report["persistence"] == "postgresql"
        assert report["build"]["status"] == "matched"
        expected = {"CWE-89", "CWE-79", "CWE-22", "CWE-601", "CWE-78"}
        verified = {i["cwe"] for i in report["issues"] if i["verification"] == "verified"}
        assert expected <= verified, report["coverage"]["gaps"]
        # This fixture has a build endpoint but no operation/input instrumentation.
        # PRD correlation pairs independent proof with source without instrumentation.
        assert report['correlation']['policy'] == 'prd'
        assert expected <= {i['cwe'] for i in report['issues'] if i['status'] == 'Confirmed'}
        assert all(i['source_link']['status'] == 'Confirmed source link' for i in report['issues']
                   if i['cwe'] in expected and i['verification'] == 'verified')
        assert any(i["cwe"] == "CWE-639" and i["verification"] == "verified" for i in report["issues"])
        assert not any(b["route"].startswith(("/safe/","/shared/")) for i in report["issues"] for b in i["bindings"])
        if previous:
            assert {i["id"] for i in report["issues"]} == previous
            assert not report["comparison"]["new"]
        previous = {i["id"] for i in report["issues"]}
    catalog=request("/api/lab")
    resource=next(r for r in catalog["resources"] if r["comparison_route"] and r["value"] == "2")
    trial=request("/api/lab/experiments","POST",{"resource_id":resource["id"],"actor":"alice","compare":True})
    assert trial["before"]["outcome"] == "violation" and trial["after"]["outcome"] == "blocked"
    assert trial["persistence"] == "postgresql"
    assert request("/api/lab/experiments")[0]["id"] == trial["id"]
    print("PASS: FastAPI, PostgreSQL, Chromium XSS, native PHP-to-shell execution proof, IDOR lab with protected-route comparison, protected decoys, and repeat-scan deduplication.")


if __name__ == "__main__":
    main()
