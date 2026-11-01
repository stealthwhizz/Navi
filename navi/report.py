from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .model import RULES


def sarif(report: dict) -> dict:
    results = []
    rules = dict(RULES)
    for issue in report["issues"]:
        rules.setdefault(issue['cwe'], (issue['title'], issue['severity'], issue['fix']))
        result = {"ruleId": issue["cwe"], "level": "error" if issue["severity"] in {"high", "critical"} else "warning",
                  "message": {"text": f'{issue["title"]} — {issue["status"]}. {issue["fix"]}'},
                  "partialFingerprints": {"navi/issue/v1": issue["id"]},
                  "properties": {"priority": issue.get('triage', {}).get('priority'), "rank": issue.get('triage', {}).get('rank'), "reasoning": issue.get("reasoning"), "status": issue["status"], "verification": issue["verification"], "linkConfidence": issue["link_confidence"], "evidence": issue["evidence"]}}
        result['properties'].update(sourceLink=issue.get('source_link'), evidenceGraph=issue.get('evidence_graph'))
        if issue["source"]:
            source = issue["source"]
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": quote(source["file"], safe="/")},
                                     "region": {"startLine": source["line"], "snippet": {"text": source["snippet"]}}}}]
        results.append(result)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "Navi", "version": __version__, "rules": [
            {"id": cwe, "name": title, "shortDescription": {"text": title}, "helpUri": f'https://cwe.mitre.org/data/definitions/{cwe.split("-")[1]}.html'}
            for cwe, (title, _, _) in rules.items()]}},
        "invocations": [{"executionSuccessful": report["status"] != "failed" and not report.get("stop_reason"), "properties": {"coverage": report["coverage"]}}], "results": results}]}


def portable_html(report: dict) -> str:
    from .reasoning import explain
    esc = lambda value: html.escape(str(value))
    cards = []
    for issue in report['issues']:
        reasoning = issue.get('reasoning') or explain(issue, report)
        where = [f"{b['method']} {b['route']} · {b['location']}: {b['parameter']}" for b in issue.get('bindings', [])]
        if issue.get('source'): where.append(f"{issue['source']['file']}:{issue['source']['line']}")
        advice = '<p><strong>AI analysis:</strong> ' + esc(reasoning['ai']) + '</p>' if reasoning.get('ai') else ''
        from .evidence import runtime_observations, primary_observation
        observations = issue.get('runtime') or runtime_observations(issue.get('evidence', []), issue.get('bindings', []))
        request = primary_observation(observations) if observations else None
        runtime = (f"<p><strong>Request:</strong> {esc(request['method'])} {esc(request['url'])}<br><strong>Parameter:</strong> {esc(request['parameter'])} ({esc(request['location'])})</p><pre>Payload: {esc(request['payload'] if request['payload'] is not None else 'Not recorded')}</pre>" if request else '')
        source = issue.get('source')
        code = f"<pre>{esc(source['file'])}:{esc(source['line'])}\n{esc(source.get('snippet', ''))}</pre>" if source else ''
        links = '<p><strong>Source attribution:</strong> ' + esc(issue.get('source_link', {}).get('status', issue['status'])) + '</p><details><summary>Source-link evidence</summary><ul>' + ''.join('<li>' + esc(r) + '</li>' for r in issue.get('link_reasons', [])) + '</ul></details>'
        if issue.get('source_link', {}).get('policy'):
            links = '<p><strong>Correlation policy:</strong> ' + esc(issue['source_link']['policy']) + '</p>' + links
        priority = issue.get('triage', {}).get('priority', '')
        cards.append(f"<article><h2>{esc(issue['title'])} <small>{esc(priority)} · {esc(issue['cwe'])} · {esc(issue['status'])} · {esc(issue['severity'])} · Risk {esc(issue['risk_score'])}/10</small></h2><p>{esc(' | '.join(where))}</p>{code}{runtime}<p><strong>Reasoning:</strong> {esc(reasoning['native'])}</p>{advice}{links}<p><strong>Suggested fix:</strong> {esc(issue['fix'])}</p><details><summary>All evidence and controls ({len(observations)})</summary><pre>{esc(json.dumps(issue, indent=2))}</pre></details></article>")
    from .console import sections
    ordered = ''.join('<section><h2>' + esc(part[0]) + '</h2><pre>' + esc('\n'.join(part[1:])) + '</pre></section>' for part in sections(report, full=True)[:5])
    data = json.dumps(report).replace('<', '\\u003c').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    summary = report['summary']
    css = 'body{background:#10151c;color:#edf2f7;font:16px/1.6 system-ui;margin:0}main{max-width:1050px;margin:auto;padding:32px}article,details{border:1px solid #344150;border-radius:12px;padding:18px;margin:16px 0}small{display:block;color:#b6c3d0;font-size:14px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}summary{cursor:pointer}h1,h2{line-height:1.3}'
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Navi report</title><style>{css}</style><main><h1>Navi · Prioritized issue queue</h1><p>{summary['total']} findings · {summary['confirmed']} Confirmed · {summary['runtime_only']} Runtime only · {summary['code_only']} Code only</p>{ordered}<h2>[6/6] Prioritized issues</h2>{''.join(cards) or '<p>No findings in the tested scope.</p>'}<details><summary>Coverage and limitations</summary><pre>{esc(json.dumps(report.get('coverage', {}), indent=2))}</pre></details><details><summary>AI review</summary><pre>{esc(json.dumps(report.get('ai', {}), indent=2))}</pre></details><script id="embedded-report" type="application/json">{data}</script></main></html>'''


def write_reports(report: dict, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    from .console import text_report
    (output / "report.txt").write_text(text_report(report))
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "report.sarif").write_text(json.dumps(sarif(report), indent=2) + "\n")
    (output / "report.html").write_text(portable_html(report))
