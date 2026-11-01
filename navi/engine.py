"""Scan lifecycle: progressive events, native checks, correlation, persistence, exports."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import time
import uuid

from .control import ScanControl, ScanStopped
from .ai import AISession
from .correlate import correlate
from .model import SCHEMA_VERSION, fingerprint, gap, no_source_analysis
from .report import write_reports
from .runtime import Runtime
from .static import analyze, source_digest
from .store import Store, compare, previous_export
from .coverage import summarize as summarize_coverage


def scan(source: str | Path | None, target: str | None, config: dict | None = None, output: str | Path = "artifacts",
         browser: bool = True, callback=None, database_url: str | None = None, transport=None, scan_id: str | None = None, project_key: str | None = None, control=None) -> dict:
    if not source and not target: raise ValueError("Provide source, target, or both.")
    config = config or {}
    if target:
        config = {**config, "discovery": config.get("discovery", {"enabled": True, "paths": ["/"], "prefixes": ["/"], "max_pages": 40, "max_candidates": 60})}
    source_path = str(Path(source).resolve()) if source else None
    from .runtime import validate_scan_options
    validate_scan_options(config)
    control = control or ScanControl(config.get("limits", {}).get("max_seconds", 300))
    stopped = None
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    scan_id = scan_id or uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    clock = time.monotonic()
    project = fingerprint(project_key or source_path or "target-only", target or "static-only")
    events_path = output / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as event_file:
        def emit(kind, data):
            event = {"scan_id": scan_id, "time": datetime.now(timezone.utc).isoformat(), "type": kind, "data": data}
            event_file.write(json.dumps(event) + "\n")
            event_file.flush()
            if callback:
                callback(event)
        configuration = {"session_configured": bool(config.get("session")), "allowed_methods": config.get("allowed_methods", ["GET"]),
                         "php_route_mappings": len(config.get("php_routes", [])), "request_seeds": len(config.get("requests", {}))}
        emit("scan_started", {"source": source_path, "target": target, "configuration": configuration})
        analysis = analyze(source, config, control=control) if source else no_source_analysis()
        template_manifests = dict(analysis.templates)
        emit("analysis", {"files": analysis.files, "routes": len(analysis.routes), "findings": len(analysis.findings), "digest": analysis.digest})
        emit("function_map", {"functions": len(analysis.function_map["nodes"]), "calls": len(analysis.function_map["edges"]),
                              "resolved_calls": sum(edge["resolved"] for edge in analysis.function_map["edges"])})
        for finding in analysis.findings:
            emit("static_finding", finding.to_dict())
        emit("analysis_complete", {"routes": [asdict(r) for r in analysis.routes], 'templates': template_manifests.get('sast', {})})
        ai = AISession(config, control, emit)
        try:
            ai_tests = ai.before(analysis, source, browser=browser)
        except Exception as error:
            ai_tests = []
            ai.fatal = f"AI preparation failed ({type(error).__name__}); native scan continues."
        runtime_findings = []
        checks = []
        discovered = {"pages": [], "inputs": []}
        gaps = [*analysis.gaps, *config.get("import_gaps", [])]
        requests = 0
        trace_summary = None
        build = {"status": "unverified", "expected": analysis.digest, "reason": "Static-only scan."}
        if target:
            runtime = None
            try:
                control.check()
                runtime = Runtime(analysis, target, config, emit=emit, browser=browser, transport=transport, control=control, source=source, ai_tests=ai_tests)
            except ScanStopped as error:
                stopped = error.kind
                gaps.append(gap("control", str(error)))
            except (ValueError, OSError) as error:
                build = {"status": "unverified", "reason": "Target transport could not be initialized."}
                gaps.append(gap("runtime", f"Target transport unavailable ({type(error).__name__}); runtime checks were not run."))
            if runtime is not None:
                runtime_findings = runtime.run()
                stopped = runtime.stop_reason
                checks = [asdict(check) for check in runtime.checks]
                gaps.extend(runtime.gaps)
                build = runtime.build
                requests = runtime.transport.count
                trace_summary = getattr(runtime.transport, 'trace_summary', None)
                discovered = {"pages": runtime.discovered_pages, "inputs": [asdict(binding) for binding in runtime.discovered_inputs]}
                if runtime.template_manifest: template_manifests['dast'] = runtime.template_manifest
        else:
            gaps.append(gap("runtime", "Static-only scan; runtime vulnerability checks were not run."))
        emit("runtime_complete", {"checks": len(checks), "verified": sum(c["outcome"] == "verified" for c in checks), "requests": requests, "skipped": not bool(target), 'templates': template_manifests.get('dast', {})})
        try:
            control.check()
        except ScanStopped as error:
            stopped = error.kind
            if not any(g["component"] == "control" for g in gaps): gaps.append(gap("control", str(error)))
        if build.get("kind") == "git" and build["status"] == "matched":
            try:
                from .identity import git_revision
                if git_revision(source) != build["expected"]: raise ValueError("revision changed")
            except (ValueError, OSError):
                build = {**build, "status": "mismatch", "reason": "Git source identity changed during the scan; source links withheld."}
                gaps.append(gap("build", build["reason"]))
        try:
            source_changed = bool(source) and source_digest(Path(source)) != analysis.digest
        except (ValueError, OSError):
            source_changed = True
        if source_changed:
            build = {**build, "status": "mismatch", "reason": "Source files changed during the scan; source links were withheld."}
            gaps.append(gap("build", build["reason"]))
        emit("correlation_started", {"ai_enabled": ai.options["enabled"]})
        from .tracing import options as trace_options
        tracing = trace_options(config.get('trace'))
        issues = correlate(analysis, runtime_findings, build, require_build_match=bool(config.get('build')),
                           trace_required=tracing['enabled'] and tracing['required'])
        for issue in issues:
            emit("issue", issue)
        coverage = {"supported_static": ["CWE-89", "CWE-79", "CWE-22", "CWE-601", "CWE-798", "CWE-78"],
                    "supported_runtime": ["CWE-89", "CWE-79", "CWE-22", "CWE-601", "CWE-639", "CWE-78"],
                    "scope": "Target-only HTTP verification with no source correlation." if not source else "Python/Flask, procedural PHP and bounded Laravel route/controller/Blade analysis; source-directed tests plus bounded form/link discovery.",
                    "limitations": ["No SCA, general stored-XSS inference, asynchronous/background entry-point analysis, or general business-policy inference. Command probes target POSIX shells; no claim of coverage for a specific recent CVE.",
                                    "Static branch reasoning is approximate. Template files, class views, dynamic routing, and application factories are not fully modeled.",
                                    "Browser verification replays HTML/CSP in isolation; same-origin scripts can be explicitly enabled through the scoped transport. Full SPA/browser authentication is not modeled."],
                    "gaps": gaps, "cwe_matrix": summarize_coverage(analysis, checks)}
        if template_manifests:
            coverage['limitations'].append('Template interpreters support a subset of upstream formats. Loaded templates are not a guarantee of full CWE coverage; ordinary HTTP matches are unverified. See the templates manifest and loading gaps.')
            if 'sast' in template_manifests:
                selected = set(template_manifests['sast'].get('cwes', [])) | {'CWE-798'}
                if any(n.get('file', '').endswith('.py') for n in analysis.function_map.get('nodes', [])):
                    selected.update(coverage['supported_static'])
                coverage['supported_static'] = sorted(selected)
            if 'dast' in template_manifests:
                coverage['supported_runtime'] = sorted(set(template_manifests['dast'].get('cwes', [])) | {'CWE-639'} | ({'CWE-79'} if config.get('stored_xss') else set()))
                coverage['runtime_proof_cwes'] = sorted(set(template_manifests['dast'].get('proof_cwes', [])) | {'CWE-639'} | ({'CWE-79'} if config.get('stored_xss') else set()))
        report = {"schema_version": SCHEMA_VERSION, "id": scan_id, "project": project, "started": started,
                  "finished": datetime.now(timezone.utc).isoformat(), "duration_seconds": round(time.monotonic() - clock, 3),
                  "status": "partial" if gaps else "completed", "stop_reason": stopped, "source": source_path, "target": target,
                  "configuration": configuration, "source_digest": analysis.digest, "source_files": analysis.files, "scan_mode": "combined" if source and target else "sast" if source else "dast", "build": build, "routes": [asdict(r) for r in analysis.routes],
                  "function_map": analysis.function_map,
                  "findings": [f.to_dict() for f in [*analysis.findings, *runtime_findings]], "issues": issues,
                  "checks": checks, "coverage": coverage, "http_requests": requests, "discovery": discovered,
                  "templates": template_manifests, "tracing": trace_summary,
                  "summary": {"total": len(issues), "confirmed": sum(i["status"] == "Confirmed" for i in issues),
                              "code_only": sum(i["status"] == "Code only" for i in issues), "runtime_only": sum(i["status"] == "Runtime only" for i in issues),
                              "verified": sum(i["verification"] == "verified" for i in issues), "coverage_gaps": len(gaps),
                              "probable_source_links": sum(i['source_link']['status'] == 'Probable source link' for i in issues)}}
        try:
            report["ai"] = ai.after(report)
        except Exception as error:
            report["ai"] = {**ai.report, "status": "unavailable", "error": f"AI review failed ({type(error).__name__}); native results retained."}
        ai_result = report["ai"]
        emit("correlation_complete", {"enabled": ai_result["enabled"], "status": ai_result["status"], "reviewed": len(ai_result.get("correlation_reviews", [])), "issues": len(issues), "requests": ai_result.get("requests", 0), "reason": ai_result.get("stages", {}).get("correlation", {}).get("reason")})
        if control.event.is_set() and not report.get("stop_reason"):
            report["stop_reason"] = "cancelled"
            report["status"] = "partial"
            gaps.append(gap("control", "Scan cancelled during AI review; completed native evidence retained."))
        from .worklist import build_worklist
        report["worklist"] = build_worklist(report)
        store = Store(database_url) if database_url else None
        previous = None
        if store:
            try:
                store.migrate()
                previous = store.previous(project)
            except Exception:
                gaps.append(gap("storage", "PostgreSQL is unavailable; file reports are retained, but history is not saved."))
                store = None
                report["status"] = "partial"
        report["persistence"] = "postgresql" if store else "exports only"
        if previous is None:
            previous = previous_export(output, project, scan_id)
        report["comparison"] = compare(previous, report)
        old_issues = {i['id']: i for i in previous['issues']} if previous else {}
        for issue in report['issues']:
            old = old_issues.get(issue['id'], {})
            issue['first_seen'] = old.get('first_seen', previous['started'] if old else started)
            issue['last_seen'] = report['finished']
        report["summary"]["coverage_gaps"] = len(gaps)
        # Include actual generation of all report formats in the PRD run time.
        write_reports(report, output)
        report["finished"] = datetime.now(timezone.utc).isoformat()
        report["duration_seconds"] = round(time.monotonic() - clock, 3)
        report["timing_scope"] = "Scan, correlation, and initial report generation; final database save and export metadata refresh excluded."
        if store:
            try:
                store.save(report)
            except Exception:
                gaps.append(gap("storage", "PostgreSQL write failed; file reports are retained."))
                report["persistence"] = "exports only"
                report["status"] = "partial"
                report["summary"]["coverage_gaps"] = len(gaps)
        write_reports(report, output)
        emit("scan_finished", {"id": scan_id, "status": report["status"], "summary": report["summary"], "duration_seconds": report["duration_seconds"]})
        return report
