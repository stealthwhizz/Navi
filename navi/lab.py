"""Interactive authorization experiments backed by the native policy verifier."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import difflib
from pathlib import Path
import re
import time
import uuid

from .model import fingerprint, no_source_analysis
from .runtime import Runtime
from .static import analyze


def resource_id(resource):
    return fingerprint("resource", resource.get("route"), resource.get("method", "GET"), resource.get("parameter"), resource.get("value"))


class AccessLab:
    def __init__(self, source, target, config, transport=None, project_key=None):
        self.source = Path(source).resolve() if source else None
        self.target = target
        self.config = config
        self.transport = transport
        self.project_key = project_key
        self.policy = config.get("authorization", {})

    def catalog(self):
        comparisons = self.config.get("lab", {}).get("comparisons", [])
        resources = []
        for resource in self.policy.get("resources", []):
            if (resource.get("method", "GET") != "GET" or not isinstance(resource.get("allowed"), list)
                    or not resource["allowed"] or not isinstance(resource.get("json_match"), dict)
                    or not resource["json_match"] or resource.get("value") is None):
                continue
            comparison = next((item for item in comparisons if item["route"] == resource.get("route")), None)
            resources.append({"id": resource_id(resource), "route": resource.get("route"), "method": "GET",
                "parameter": resource.get("parameter"), "value": resource.get("value"), "allowed": resource.get("allowed", []),
                "protected_fields": list(resource.get("json_match", {})),
                "comparison_route": comparison["protected_route"] if comparison else None})
        return {"identities": [{"id": name, "label": name.replace("_", " ").title()} for name in self.policy.get("identities", {})],
                "resources": resources, "available": bool(resources and len(self.policy.get("identities", {})) >= 2),
                "policy": "Access expectations come from the supplied policy. Identities are verified before resource tests.",
                "target": self.target}

    def context(self, analysis, route):
        if self.source is None: return None
        handler = next((r for r in analysis.routes if r.path == route and "GET" in r.methods), None)
        if not handler:
            return None
        base = self.source.parent if self.source.is_file() else self.source
        file = (base / handler.file).resolve()
        if not file.is_relative_to(base):
            return None
        lines = file.read_text().splitlines()
        snippet = "\n".join(lines[handler.line - 1: min(handler.end_line, handler.line + 65)])
        # Do not expose configured authentication header values through code views.
        for identity in self.policy.get("identities", {}).values():
            for value in identity.get("headers", {}).values():
                if isinstance(value, str) and len(value) >= 12:
                    snippet = snippet.replace(value, "[redacted]")
        return {"file": handler.file, "line": handler.line, "function": handler.function, "snippet": snippet,
                "role": "Route-handler context. A missing authorization operation is not inferred from this map alone."}

    def _observe(self, analysis, resource, actor):
        config = deepcopy(self.config)
        config["authorization"]["resources"] = [resource]
        runtime = Runtime(analysis, self.target, config, browser=False, transport=self.transport, source=self.source)
        runtime.check_build()
        runtime.authorization()
        checks = [asdict(check) for check in runtime.checks]
        evidence = []
        for check in checks:
            for item in check["evidence"]:
                if item not in evidence:
                    evidence.append(item)
        observed = next((e for e in evidence if e["request"].get("identity") == actor), None)
        baseline = next((e for e in evidence if e["request"].get("identity") in resource.get("allowed", [])), None)
        expected = "allow" if actor in resource.get("allowed", []) else "deny"
        relevant = next((c for c in checks if any(e.get("policy", {}).get("requester") == actor for e in c["evidence"])), None)
        outcome = "inconclusive"
        reason = "The identity or successful access baseline could not be established."
        if observed and baseline and expected == "deny" and relevant:
            outcome = {"verified": "violation", "not_reproduced": "blocked"}.get(relevant["outcome"], "inconclusive")
            reason = relevant["reason"]
        elif observed and expected == "allow" and observed["status"] == 200:
            # A baseline recorded under an invalid policy must not become a passing experiment.
            valid = not any(c["outcome"] in {"error", "inconclusive"} for c in checks)
            if valid:
                outcome, reason = "permitted", "The identity received the object and is explicitly allowed by the supplied policy."
        return {"route": resource["route"], "outcome": outcome, "expected": expected, "reason": reason,
                "actor": actor, "allowed": resource.get("allowed", []), "protected_fields": list(resource.get("json_match", {})),
                "request": observed, "baseline": baseline, "checks": checks, "build": runtime.build,
                "source": self.context(analysis, resource["route"]), "http_requests": runtime.transport.count}

    def experiment(self, selected_resource, actor, compare=False):
        resource = next((r for r in self.policy.get("resources", []) if resource_id(r) == selected_resource), None)
        if not resource or actor not in self.policy.get("identities", {}):
            raise ValueError("Select an identity and resource from the configured policy.")
        if resource.get("method", "GET") != "GET":
            raise ValueError("Access-lab experiments support read-only GET policies.")
        start = time.monotonic()
        analysis = analyze(self.source, self.config) if self.source else no_source_analysis()
        before = self._observe(analysis, deepcopy(resource), actor)
        result = {"id": uuid.uuid4().hex, "resource_id": selected_resource, "actor": actor,
                  "project": fingerprint(self.project_key or (str(self.source) if self.source else "target-only"), self.target), "created": datetime.now(timezone.utc).isoformat(),
                  "mode": "live requests", "before": before, "after": None, "comparison": None,
                  "function_map": analysis.function_map, "routes": [asdict(r) for r in analysis.routes], "source_digest": analysis.digest}
        if compare:
            alternative = next((r for r in self.config.get("lab", {}).get("comparisons", []) if r["route"] == resource["route"]), None)
            if not alternative:
                raise ValueError("No protected implementation is configured for this resource.")
            if not any(r.path == alternative["protected_route"] and "GET" in r.methods for r in analysis.routes):
                raise ValueError("The configured protected route is absent from the analyzed application.")
            protected = {**resource, "route": alternative["protected_route"]}
            after = self._observe(analysis, protected, actor)
            result["after"] = after
            diff = []
            if before["source"] and after["source"]:
                diff = list(difflib.unified_diff(before["source"]["snippet"].splitlines(), after["source"]["snippet"].splitlines(),
                    fromfile=before["source"]["function"], tofile=after["source"]["function"], lineterm=""))
            result["comparison"] = {"verified": before["outcome"] == "violation" and after["outcome"] == "blocked",
                "source_diff": diff, "kind": "protected implementation comparison",
                "note": "The same actor, object reference, and access policy were tested on two configured routes. This does not edit the application or certify all authorization paths."}
        result["duration_seconds"] = round(time.monotonic() - start, 3)
        return result
