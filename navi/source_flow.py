"""Bounded, per-input provenance DAGs produced by the native taint interpreters.

These describe modeled value propagation, not execution or exploitability.
Unknown transformations and exhausted bounds remain explicitly incomplete.
"""
from dataclasses import dataclass, replace

from .model import fingerprint


@dataclass(frozen=True)
class Flow:
    nodes: tuple = ()
    edges: tuple = ()
    heads: tuple = ()
    complete: bool = True


def union(flows):
    flows = list(flows)
    nodes = tuple(dict.fromkeys(n for f in flows for n in f.nodes))
    edges = tuple(dict.fromkeys(e for f in flows for e in f.edges))
    heads = tuple(dict.fromkeys(h for f in flows for h in f.heads))
    complete = all(f.complete for f in flows) and len(nodes) <= 64 and len(edges) <= 128
    nodes = nodes[:64]
    ids = {n[0] for n in nodes}
    return Flow(nodes, tuple(e for e in edges[:128] if set(e) <= ids), tuple(h for h in heads if h in ids), complete)


def combine_flows(values):
    result = {}
    for value in values:
        for inp in value.inputs:
            flow = value.flows.get(inp, Flow(complete=False))
            result[inp] = union([result[inp], flow]) if inp in result else flow
    return result


def step(value, file, line, label, column=0, kind='propagation'):
    flows = {}
    for inp in value.inputs:
        prior = value.flows.get(inp)
        node_kind = kind if prior is not None else 'input_source'
        identity = fingerprint('flow', file, line, column, label, inp.location, inp.name, node_kind)
        node = (identity, node_kind, file, line, column, label[:300])
        if prior is None:
            flows[inp] = Flow((node,), (), (identity,), inp.name != '*')
        elif identity in {n[0] for n in prior.nodes}:
            flows[inp] = prior
        else:
            added = union([prior, Flow((node,), tuple((h, identity) for h in prior.heads), (identity,))])
            flows[inp] = replace(added, heads=(identity,) if identity in {n[0] for n in added.nodes} else added.heads)
    return replace(value, flows=flows)


def incomplete(value):
    return replace(value, flows={inp: replace(value.flows.get(inp, Flow()), complete=False) for inp in value.inputs})


def record(finding, binding, value, inp):
    """Persist only the tested input's DAG and its exact sensitive operation."""
    flow = value.flows.get(inp, Flow(complete=False))
    source = finding.source
    sink = fingerprint('sink', finding.id)
    nodes = [dict(zip(('id', 'kind', 'file', 'line', 'column', 'label'), n)) for n in flow.nodes]
    nodes.append({'id': sink, 'kind': 'sensitive_sink', **source, 'operation_id': finding.id})
    http = fingerprint('http-input', binding.route, binding.method, inp.location, inp.name)
    nodes.insert(0, {'id': http, 'kind': 'http_input', 'route': binding.route, 'method': binding.method,
                     'location': inp.location, 'parameter': inp.name})
    edges = [{'from': a, 'to': b, 'kind': 'modeled_data_flow'} for a, b in flow.edges]
    edges += [{'from': h, 'to': sink, 'kind': 'sink_argument'} for h in flow.heads]
    edges += [{'from': http, 'to': n[0], 'kind': 'input_binding'} for n in flow.nodes if n[1] == 'input_source']
    graph = {'version': 1, 'operation_id': finding.id,
             'binding': {k: getattr(binding, k) for k in ('route', 'method', 'location', 'parameter')},
             'complete': bool(flow.nodes) and flow.complete and binding.provenance not in {'configured', 'unmapped'},
             'nodes': nodes, 'edges': edges,
             'scope': 'Bounded static value propagation; branch feasibility and runtime causality require execution evidence.'}
    if graph not in finding.source_flows:
        finding.source_flows.append(graph)


def matching(finding, keys):
    return [g for g in finding.source_flows if g.get('operation_id') == finding.id and
            tuple(g['binding'][k] for k in ('route', 'method', 'location', 'parameter')) in keys and
            any(n.get('kind') == 'sensitive_sink' and n.get('operation_id') == finding.id and
                n.get('file') == finding.source.get('file') and n.get('line') == finding.source.get('line')
                for n in g.get('nodes', []))]
