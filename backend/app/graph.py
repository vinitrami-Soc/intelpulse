"""Builds the Cytoscape.js relationship graph for an investigation.

The point of the graph is the question an analyst asks third: "is this one
thing, or is it the same thing five times?" Shared malware families, ASNs and
payload hashes are what reveal that, so those become nodes and every indicator
that touches one gets an edge to it.
"""
from __future__ import annotations

from collections.abc import Iterable

from .enrichment.base import ProviderResult
from .scoring import IndicatorVerdict

_NODE_COLORS = {
    "critical": "#ff4d4d",
    "high": "#ff8c42",
    "medium": "#ffd166",
    "low": "#4cc9f0",
    "informational": "#7d8597",
    "allowlisted": "#3ddc97",
}
_TYPE_SHAPES = {
    "ip": "ellipse",
    "domain": "round-rectangle",
    "url": "diamond",
    "hash": "hexagon",
    "email": "octagon",
    "cve": "triangle",
    "malware": "star",
    "actor": "star",
    "asn": "round-rectangle",
    "country": "round-rectangle",
    "pulse": "round-rectangle",
}


def build_graph(
    verdicts: Iterable[IndicatorVerdict],
    results_by_ioc: dict[str, list[ProviderResult]],
) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, label: str, kind: str, **extra) -> None:
        if node_id in nodes:
            nodes[node_id]["data"].update({k: v for k, v in extra.items() if v is not None})
            return
        nodes[node_id] = {
            "data": {
                "id": node_id,
                "label": label[:48],
                "kind": kind,
                "shape": _TYPE_SHAPES.get(kind, "ellipse"),
                **extra,
            }
        }

    def add_edge(source: str, target: str, relation: str, confidence: float) -> None:
        edge_id = f"{source}->{target}:{relation}"
        if any(e["data"]["id"] == edge_id for e in edges):
            return
        edges.append(
            {
                "data": {
                    "id": edge_id,
                    "source": source,
                    "target": target,
                    "label": relation.replace("_", " "),
                    "confidence": confidence,
                }
            }
        )

    for verdict in verdicts:
        ioc = verdict.indicator.value
        node_id = f"ioc:{ioc}"
        add_node(
            node_id,
            ioc,
            verdict.indicator.type,
            score=verdict.score,
            verdict=verdict.verdict,
            color=_NODE_COLORS.get(verdict.verdict, "#7d8597"),
            root=True,
        )

        for result in results_by_ioc.get(ioc, []):
            if not result.answered:
                continue
            for relation in result.relations:
                target_id = (
                    f"ioc:{relation.target}"
                    if relation.target_type in ("ip", "domain", "url", "hash", "email", "cve")
                    else f"{relation.target_type}:{relation.target}"
                )
                add_node(
                    target_id,
                    relation.target,
                    relation.target_type,
                    color=_NODE_COLORS.get("medium" if relation.confidence > 0.7 else "informational"),
                    source_provider=result.provider,
                )
                add_edge(node_id, target_id, relation.relation, relation.confidence)

    return {"nodes": list(nodes.values()), "edges": edges}
