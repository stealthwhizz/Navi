from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import threading
import signal
import uuid

from .engine import scan
from .runtime import load_config
from .console import ConsoleProgress, summarize


def main(argv=None):
    from .environment import load_environment
    load_environment()
    parser = argparse.ArgumentParser(prog="navi", description="Native source analysis, runtime verification, and evidence correlation.")
    commands = parser.add_subparsers(dest="command", required=True)

    def storage(p):
        p.add_argument('--scanner', choices=['templates', 'native'], help='Native scanner mode; new CLI scans default to local templates')
        p.add_argument('--sast-rules', action='append', help='Local Semgrep-style PHP taint YAML interpreted by Navi (repeatable)')
        p.add_argument('--dast-templates', action='append', help='Local Nuclei-style HTTP YAML interpreted by Navi (repeatable)')
        p.add_argument('--ai-provider', choices=['groq', 'openai'], help='AI provider; defaults to Groq')
        p.add_argument("--document-root", help="PHP web root relative to --source (for example public); defaults to the source directory")
        p.add_argument("--openapi", help="Local OpenAPI 3 JSON file supplying API inputs and baseline examples")
        p.add_argument("--allow-origin", action="append", help="Explicitly authorize an additional exact HTTP(S) origin")
        p.add_argument("--allow-method", action="append", choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], help="Enable an additional HTTP method for configured/API tests")
        ai_group = p.add_mutually_exclusive_group()
        ai_group.add_argument("--ai", dest="ai", action="store_true", default=None, help="Enable Groq correlation reasoning; requires GROQ_API_KEY")
        ai_group.add_argument("--no-ai", dest="ai", action="store_false", help="Run the native engine without model calls")
        p.add_argument("--ai-model", help="Provider model ID; Groq defaults to openai/gpt-oss-20b")
        p.add_argument("--database-url", default=os.getenv("DATABASE_URL"), help="PostgreSQL DSN; defaults to DATABASE_URL. Omit for explicit exports-only operation.")
        p.add_argument("--output", help="Report root; scans are retained under scans/<id>/")
        p.add_argument("--no-browser", action="store_true", help="Skip Chromium execution checks; report an XSS coverage gap")

    scan_parser = commands.add_parser("scan", help="Scan source, a running HTTP(S) application, or both")
    scan_parser.add_argument("--source")
    scan_parser.add_argument("--project", help="Versioned project JSON; defaults to navi.json when source and target are omitted")
    scan_parser.add_argument("--target", help="HTTP(S) target; non-loopback origins require explicit scope")
    scan_parser.add_argument("--config", help="JSON request seeds, build identity, fixtures, and authorization policy")
    scan_parser.add_argument("--json-events", action="store_true", help="Emit machine-readable events to stdout; the explanation remains on stderr")
    scan_parser.add_argument("--verbose", action="store_true", help="Show every runtime check and its reason")
    scan_parser.add_argument("--fail-on-confirmed-high", action="store_true")
    scan_parser.add_argument("--fail-on-verified-high", action="store_true", help="Exit 1 for high/critical runtime proof, including Runtime only issues")
    scan_parser.add_argument("--require-complete", action="store_true", help="Exit 3 when coverage is partial")
    storage(scan_parser)

    serve_parser = commands.add_parser("serve", help="Start the FastAPI dashboard and API")
    serve_parser.add_argument("--source")
    serve_parser.add_argument("--project")
    serve_parser.add_argument("--target")
    serve_parser.add_argument("--config")
    serve_parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "0.0.0.0"])
    serve_parser.add_argument("--port", type=int, help="Dashboard port; default tries 8080–8089. Use 0 for any available port.")
    serve_parser.add_argument("--allowed-host", action="append", default=[], help="Additional dashboard hostname; requires NAVI_API_TOKEN")
    storage(serve_parser)

    migrate_parser = commands.add_parser("migrate", help="Apply the PostgreSQL schema")
    migrate_parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"))

    init_parser = commands.add_parser("init", help="Create a reusable project file without scanning")
    init_parser.add_argument("--source", help="Source directory; omit for HTTP-only testing")
    init_parser.add_argument("--ai", action="store_true", help="Enable Groq reviews in the generated project")
    init_parser.add_argument("--openapi", help="Local OpenAPI 3 JSON path to retain in the project")
    init_parser.add_argument("--target")
    init_parser.add_argument("--config")
    init_parser.add_argument("--project", default="navi.json")
    for name in ("plan", "doctor"):
        command = commands.add_parser(name, help="Inspect native test candidates" if name == "plan" else "Check source, target, browser, and PostgreSQL readiness")
        command.add_argument("--project")
        command.add_argument("--source")
        command.add_argument("--target")
        command.add_argument("--config")
        command.add_argument("--save", help="Also write JSON to this file")
        storage(command)
    compare_parser = commands.add_parser("compare", help="Compare saved reports from the same project")
    compare_parser.add_argument("previous")
    compare_parser.add_argument("current")
    evaluation = commands.add_parser("evaluate", help="Score a saved report against a separate answer key")
    evaluation.add_argument("report")
    evaluation.add_argument("--answer-key", required=True)
    evaluation.add_argument("--save")
    evaluation.add_argument("--unseen-report")
    evaluation.add_argument("--unseen-answer-key")
    evaluation.add_argument("--require", choices=["good", "great"], help="Exit 3 unless every PRD metric for this level is available and passes")

    report_parser = commands.add_parser("report", help="Explain a saved JSON report without scanning or making AI requests")
    report_parser.add_argument("path", nargs="?", help="Saved report.json; defaults to the current project's latest report")
    report_parser.add_argument("--project", help="Project file used to locate the latest saved report")

    ai_check = commands.add_parser("ai-check", help="Check provider credentials and JSON response using synthetic data only")
    ai_check.add_argument("--offline", action="store_true", help="Diagnose local key selection without sending any request or showing the key")
    ai_check.add_argument('--provider', choices=['groq', 'openai'], default='groq')
    ai_check.add_argument("--model")
    args = parser.parse_args(argv)
    try:
        from .project import resolve, initialize, plan, doctor
        if args.command == "report":
            path = args.path
            if not path:
                from .project import load_project
                project_path = args.project or "navi.json"
                project = load_project(project_path) if Path(project_path).is_file() else {}
                if args.project and not project: raise ValueError("Project file not found.")
                path = Path(project.get("output", "artifacts")) / "report.json"
            path = Path(path)
            if path.is_dir(): path = path / "report.json"
            saved = json.loads(path.read_text())
            if not isinstance(saved, dict) or not {"summary", "issues", "coverage"} <= saved.keys():
                raise ValueError("Expected a Navi report.json file.")
            summarize(saved, path.parent, source_file=path)
            return 0
        if args.command == "ai-check":
            from .ai.client import create_client, AIUnavailable
            from .ai.config import options
            from .control import ScanControl
            from .environment import credential_status
            selected = options({'enabled': True, 'provider': args.provider, **({'model': args.model} if args.model else {})})
            args.model = selected['model']
            diagnostic = credential_status(selected['api_key_env'], selected['provider'])
            if args.offline:
                output_json({"provider": args.provider, "model": args.model, "provider_checked": False, "requests": 0, **diagnostic})
                return 0 if diagnostic['local_configuration_ok'] else 2
            try:
                client = create_client(selected)
                result, usage = client.complete([{"role": "system", "content": 'Return only JSON: {"ready":true}. This is a connectivity check with no source or target data.'}, {"role": "user", "content": "Return the readiness JSON."}], ScanControl(30))
                ready = result == {"ready": True}
                output_json({"ready": ready, "provider": args.provider, "model": args.model, "usage": usage, "source_uploaded": False, "key_selection": diagnostic})
                return 0 if ready else 2
            except AIUnavailable as error:
                output_json({"ready": False, "provider": args.provider, "reason": str(error), "source_uploaded": False, "key_selection": diagnostic})
                return 2
        if args.command == "init":
            initialize(args.project, args.source, args.target, args.config, args.openapi, ai=args.ai)
            print(f"Project created: {Path(args.project).resolve()}")
            return 0
        if args.command in {"plan", "doctor"}:
            project = resolve(args)
            result = plan(project["source"], project["target"], project["config"], not args.no_browser) if args.command == "plan" else doctor(
                project["source"], project["target"], project["config"], args.database_url, not args.no_browser)
            output_json(result, args.save)
            return 0 if result.get("ready", True) else 2
        if args.command == "compare":
            from .store import compare
            previous, current = (json.loads(Path(p).read_text()) for p in (args.previous, args.current))
            if previous["project"] != current["project"]: raise ValueError("Reports belong to different projects/targets.")
            output_json({**compare(previous, current), "previous_status": previous["status"], "current_status": current["status"]})
            return 0
        if args.command == "evaluate":
            from .evaluate import evaluate
            result = evaluate(json.loads(Path(args.report).read_text()), json.loads(Path(args.answer_key).read_text()),
                              json.loads(Path(args.unseen_report).read_text()) if args.unseen_report else None,
                              json.loads(Path(args.unseen_answer_key).read_text()) if args.unseen_answer_key else None)
            output_json(result, args.save)
            return 3 if args.require and (not result["thresholds"][args.require]["all_thresholds_pass"] or not result["answer_key_complete"] or result["stop_reason"] or (result["unseen"] and result["unseen"]["stop_reason"])) else 0
        if args.command == "migrate":
            if not args.database_url:
                raise ValueError("Set DATABASE_URL or provide --database-url.")
            from .store import Store
            Store(args.database_url).migrate()
            print("PostgreSQL schema is ready.")
            return 0
        if args.command == "serve":
            project = resolve(args)
            if not project["target"]: raise ValueError("The dashboard requires a configured target.")
            args.output = project["output"]
            args.project_key = project["project_key"]
            args.ai_options = project["config"].get("ai")
            args.scan_config = project["config"]
            return serve(args, project["source"], project["target"], project["config_path"])
        callback = (lambda event: print(json.dumps(event), flush=True)) if args.json_events else ConsoleProgress(args.verbose)
        project = resolve(args)
        from .control import ScanControl
        control = ScanControl(project["config"].get("limits", {}).get("max_seconds", 300))
        scan_id = uuid.uuid4().hex
        destination = Path(project["output"]) / "scans" / scan_id
        with graceful_interrupt(control):
            report = scan(project["source"], project["target"], project["config"], destination, browser=not args.no_browser,
                          callback=callback, database_url=args.database_url, scan_id=scan_id, project_key=project["project_key"], control=control)
        # Retain legacy latest-report paths while preserving every immutable run.
        import shutil
        for filename in ("report.json", "report.html", "report.txt", "report.sarif", "events.jsonl"):
            temporary = Path(project["output"]) / f".{scan_id}-{filename}"
            shutil.copyfile(destination / filename, temporary)
            temporary.chmod(0o600)
            temporary.replace(Path(project["output"]) / filename)
        summarize(report, destination, phases_printed=not args.json_events, full=args.verbose)
        if report.get("stop_reason") == "cancelled": return 130
        if report.get("stop_reason"): return 3
        if args.fail_on_verified_high and any(i["verification"] == "verified" and i["severity"] in {"high", "critical"} for i in report["issues"]):
            return 1
        if args.fail_on_confirmed_high and any(i["status"] == "Confirmed" and i["severity"] in {"high", "critical"} for i in report["issues"]):
            return 1
        return 3 if args.require_complete and report["status"] == "partial" else 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Never print a PostgreSQL DSN or a credential-containing connection exception.
        if isinstance(error, (ValueError, FileNotFoundError, json.JSONDecodeError)):
            print(f"navi: {error}", file=sys.stderr)
        else:
            print(f"navi: {type(error).__name__}. Check configuration, local service availability, and file permissions.", file=sys.stderr)
        return 2


def serve(args, source, target, config):
    import uvicorn
    from .api import Settings, create_app
    if args.host == "0.0.0.0" and not os.getenv("NAVI_API_TOKEN"):
        raise ValueError("Binding the workspace to all interfaces requires NAVI_API_TOKEN.")
    from .server import dashboard_socket
    with dashboard_socket(args.host, args.port) as listener:
        application = create_app(Settings(source=source, target=target, config_path=config, output=args.output,
                                         database_url=args.database_url, browser=not args.no_browser,
                                         project_key=getattr(args, "project_key", None),
                                         ai=getattr(args, "ai_options", None), scan_config=getattr(args, "scan_config", None),
                                         api_token=os.getenv("NAVI_API_TOKEN"), allowed_hosts=tuple(getattr(args, "allowed_host", []))))
        chosen_port = listener.getsockname()[1]
        if args.port is None and chosen_port != 8080:
            print(f"Dashboard port 8080 is occupied; using {chosen_port}.", file=sys.stderr)
        print(f"Navi dashboard: http://127.0.0.1:{chosen_port}", file=sys.stderr)
        server = uvicorn.Server(uvicorn.Config(application, host=args.host, port=chosen_port, workers=1, log_level="info"))
        server.run(sockets=[listener])
    return 0


def output_json(value, destination=None):
    text = json.dumps(value, indent=2)
    if destination:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n")
    print(text)


@contextmanager
def graceful_interrupt(control):
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGINT)
    def stop(signum, frame):
        control.cancel()
        print("Stopping scan; saving completed evidence…", file=sys.stderr)
    signal.signal(signal.SIGINT, stop)
    try: yield
    finally: signal.signal(signal.SIGINT, previous)
