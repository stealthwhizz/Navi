"""Independent answer-key scoring. This module is never imported by scanners."""
from .model import RULES

KINDS = {"paired", "code_only", "runtime_only", "decoy"}
RUNTIME_FIELDS = {"route", "method", "parameter", "location"}
THRESHOLDS = {
    "good": {"code_recall": (">", 60), "runtime_recall": (">", 50), "correct_links": (">", 50),
             "wrong_links": ("<", 20), "decoy_issue_share": ("<", 30), "unseen_pairs": (">", 40), "duration_seconds": ("<", 900)},
    "great": {"code_recall": (">", 85), "runtime_recall": (">", 80), "correct_links": (">", 80),
              "wrong_links": ("<", 5), "decoy_issue_share": ("<", 10), "unseen_pairs": (">", 65), "duration_seconds": ("<", 300)},
}


def validate_key(key):
    if not isinstance(key, dict) or key.get("version") != 1 or not isinstance(key.get("cases"), list):
        raise ValueError("Answer key requires version 1 and a cases list.")
    dataset = key.get("dataset", {})
    if not isinstance(dataset, dict) or not dataset.get("name") or not dataset.get("provenance") or dataset.get("partition") not in {"local", "provided", "unseen"}:
        raise ValueError("Dataset requires name, provenance, and partition (local/provided/unseen).")
    if type(key.get("complete")) is not bool: raise ValueError("Answer key must declare whether coverage is complete.")
    ids, anchors = set(), set()
    for case in key["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"] or case["id"] in ids:
            raise ValueError("Every answer-key case requires a unique nonempty id.")
        ids.add(case["id"])
        if case.get("kind") not in KINDS or case.get("cwe") not in RULES: raise ValueError("Invalid case kind or CWE.")
        source, runtime = case.get("source"), case.get("runtime")
        if (case["kind"] in {"paired", "code_only"} and source is None) or (case["kind"] in {"paired", "runtime_only"} and runtime is None):
            raise ValueError("Case lacks the source or runtime anchor required by its kind.")
        if case["kind"] == "code_only" and runtime or case["kind"] == "runtime_only" and source: raise ValueError("Single-channel cases must have only their own anchor.")
        if source is None and runtime is None: raise ValueError("Decoys also require an observable source or runtime anchor.")
        if source is not None:
            if (not isinstance(source, dict) or source.keys() - {"file", "line", "function"}
                    or not isinstance(source.get("file"), str) or source["file"].startswith("/") or ".." in source["file"].split("/")
                    or type(source.get("line")) is not int or source["line"] < 1): raise ValueError("Source anchors need relative file and positive line, with optional function.")
            anchor = (case["cwe"], "source", source["file"], source["line"])
            if anchor in anchors: raise ValueError("Duplicate source anchors would inflate recall; use one case per operation.")
            anchors.add(anchor)
        if runtime is not None:
            if not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS or any(not isinstance(v, str) for v in runtime.values()):
                raise ValueError("Runtime anchors require route, method, parameter, and location.")
            anchor = (case["cwe"], "runtime", *(runtime[k] for k in sorted(RUNTIME_FIELDS)))
            if anchor in anchors: raise ValueError("Duplicate runtime anchors would inflate recall; use one case per input/CWE.")
            anchors.add(anchor)


def evaluate(report, key, unseen_report=None, unseen_key=None):
    validate_key(key)
    if report.get("schema_version") not in {"1.0", "1.1", "1.2"} or not isinstance(report.get("findings"), list) or not isinstance(report.get("issues"), list):
        raise ValueError("A Navi schema 1.x report is required.")
    cases = key["cases"]
    findings = {f["id"]: f for f in report["findings"]}
    matches = {}
    for finding in findings.values():
        hits = []
        for case in cases:
            if finding["cwe"] != case["cwe"]: continue
            anchor = case.get("source" if finding["origin"] == "sast" else "runtime")
            if not anchor: continue
            if finding["origin"] == "sast":
                matched = all((finding.get("source") or {}).get(k) == v for k, v in anchor.items())
            else:
                matched = finding.get("verification") == "verified" and any(all(b.get(k) == v for k, v in anchor.items()) for b in finding.get("bindings", []))
            if matched: hits.append(case["id"])
        matches[finding["id"]] = hits[0] if len(hits) == 1 else None
    detected_code = {matches[f["id"]] for f in findings.values() if f["origin"] == "sast"} - {None}
    detected_runtime = {matches[f["id"]] for f in findings.values() if f["origin"] == "dast" and f.get("verification") == "verified"} - {None}
    pairs = {c["id"] for c in cases if c["kind"] == "paired"}
    code = {c["id"] for c in cases if c["kind"] in {"paired", "code_only"}}
    runtime = {c["id"] for c in cases if c["kind"] in {"paired", "runtime_only"}}
    decoys = {c["id"] for c in cases if c["kind"] == "decoy"}
    correct, correct_issues, wrong, unknown, false_reports = set(), [], [], [], []
    confirmed = [i for i in report["issues"] if i["status"] == "Confirmed"]
    for issue in report["issues"]:
        members = [findings[f] for f in issue.get("findings", []) if f in findings]
        identifiers = {matches[f["id"]] for f in members}
        if identifiers & decoys: false_reports.append(issue["id"])
        if issue["status"] != "Confirmed": continue
        origins = {f["origin"] for f in members}
        if len(identifiers) == 1 and identifiers <= pairs and origins == {"sast", "dast"}:
            correct.update(identifiers)
            correct_issues.append(issue['id'])
        elif len(identifiers - {None}) > 1:
            wrong.append(issue["id"])
        elif None in identifiers or origins != {"sast", "dast"} or not identifiers:
            unknown.append(issue["id"])
        # A linked source/runtime decoy is a false alarm, not two different bugs.
    def ratio(n, d, reason=None):
        return {"numerator": n, "denominator": d, "percent": round(100 * n / d, 3) if d else None,
                "unavailable_reason": reason if not d else None}
    metrics = {"code_recall": ratio(len(code & detected_code), len(code), "No code cases."),
               "runtime_recall": ratio(len(runtime & detected_runtime), len(runtime), "No runtime cases."),
               "correct_links": ratio(len(correct), len(pairs), "No paired cases."),
               "wrong_links": ratio(len(wrong), len(confirmed), "No confirmed links."),
               "decoy_issue_share": ratio(len(false_reports), len(report["issues"]), "No reported issues."),
               "unseen_pairs": ratio(len(correct), len(pairs) if key["dataset"]["partition"] == "unseen" else 0, "Requires a separate unseen dataset."),
               "duration_seconds": report.get("duration_seconds")}
    if not decoys:
        metrics["decoy_issue_share"].update(percent=None, unavailable_reason="No safe decoys in answer key.")
    if unknown:
        metrics["wrong_links"].update(percent=None, unavailable_reason="Some links are outside the supplied truth; wrong-link rate is unknown.")
    metrics['link_accuracy'] = ratio(len(correct_issues), len(confirmed), 'No confirmed source links.')
    if unknown:
        metrics['link_accuracy'].update(percent=None, unavailable_reason='Some confirmed links are outside the supplied truth.')
    for channel, origin, truth in [('code', 'sast', code), ('runtime', 'dast', runtime)]:
        selected = [f for f in findings.values() if f['origin'] == origin and
                    (origin == 'sast' or f.get('verification') == 'verified')]
        precision = ratio(sum(matches[f['id']] in truth for f in selected), len(selected), 'No findings in this channel.')
        if not key['complete'] and any(matches[f['id']] is None for f in selected):
            precision.update(percent=None, unavailable_reason='Incomplete answer key: unmatched findings have unknown truth.')
        metrics[channel + '_precision'] = precision
    unseen = None
    if (unseen_report is None) != (unseen_key is None): raise ValueError("Supply both unseen report and unseen answer key.")
    if unseen_report is not None:
        validate_key(unseen_key)
        if unseen_key["dataset"]["partition"] != "unseen": raise ValueError("The second answer key must declare partition unseen.")
        if unseen_report["id"] == report["id"] or (report.get("source_digest") and unseen_report.get("source_digest") == report["source_digest"]):
            raise ValueError("The unseen run must analyze a different application snapshot.")
        result = evaluate(unseen_report, unseen_key)
        metrics["unseen_pairs"] = result["metrics"]["correct_links"]
        unseen = {"scan_id": unseen_report["id"], "dataset": unseen_key["dataset"], "answer_key_complete": unseen_key["complete"],
                  "scan_partial": result["scan_partial"], "stop_reason": result["stop_reason"], "metrics": result["metrics"]}
    grades = {}
    for name, thresholds in THRESHOLDS.items():
        results = {}
        for metric, (operator, threshold) in thresholds.items():
            value = metrics[metric] if metric == "duration_seconds" else metrics[metric]["percent"]
            results[metric] = {"requirement": f"{operator} {threshold}", "passes": None if value is None else value > threshold if operator == ">" else value < threshold}
        values = [r["passes"] for r in results.values()]
        grades[name] = {"metrics": results, "all_measured_thresholds_pass": False not in values,
                        "all_thresholds_pass": all(v is True for v in values)}
    return {"version": 1, "scan_id": report["id"], "dataset": key["dataset"], "answer_key_complete": key["complete"] and (unseen is None or unseen["answer_key_complete"]), "unseen": unseen,
            "metrics": metrics, "thresholds": grades,
            "cases": [{"id": c["id"], "kind": c["kind"], "code_observed": c["id"] in detected_code,
                       "runtime_observed": c["id"] in detected_runtime, "correctly_linked": c["id"] in correct} for c in cases],
            "wrong_link_issue_ids": wrong, "unassessed_link_issue_ids": unknown, "decoy_issue_ids": false_reports,
            "probable_source_link_issue_ids": [i['id'] for i in report['issues'] if i.get('source_link', {}).get('status') == 'Probable source link'],
            "unmatched_finding_ids": [f for f, match in matches.items() if match is None],
            "scan_partial": report.get("status") != "completed", "stop_reason": report.get("stop_reason"),
            "note": "Scores describe only this answer key and run. Local fixtures do not establish organiser qualification. Decoy issue share is known-decoy reports / all reports, not population false-positive rate. No unseen score is inferred from a provided/local app."}
