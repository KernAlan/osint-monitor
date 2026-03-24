"""NetworkX knowledge graph queries."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import Callable

import networkx as nx
from networkx.algorithms.community import louvain_communities
from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Entity, EntityRelationship, Event, EventEntity, ItemEntity, RawItem,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Transitive inference rules: (rel_type_1, rel_type_2) -> inferred_rel_type
# ---------------------------------------------------------------------------
TRANSITIVE_RULES: dict[tuple[str, str], str] = {
    ("funds", "arms"): "indirectly_supports",
    ("funds", "funds"): "indirectly_funds",
    ("commands", "operates_in"): "has_presence_in",
    ("commands", "commands"): "indirect_command",
    ("allied_with", "funds"): "indirectly_funds_ally",
    ("allied_with", "arms"): "indirectly_arms_ally",
    ("member_of", "operates_in"): "has_presence_in",
    ("funds", "operates_in"): "funds_operations_in",
    ("subsidiary_of", "operates_in"): "has_presence_in",
    ("commands", "funds"): "directs_funding",
    ("allied_with", "allied_with"): "second_degree_ally",
    ("employs", "operates_in"): "has_presence_in",
}

# Co-occurrence threshold for strong relationship inference
CO_OCCURRENCE_STRONG_THRESHOLD = 3


# ---------------------------------------------------------------------------
# Core graph building
# ---------------------------------------------------------------------------

def build_entity_graph(session: Session) -> nx.DiGraph:
    """Build a directed graph from entities and their relationships."""
    G = nx.DiGraph()

    # Add all entities as nodes
    entities = session.query(Entity).all()
    for ent in entities:
        G.add_node(ent.id, **{
            "name": ent.canonical_name,
            "type": ent.entity_type,
            "aliases": ent.aliases or [],
            "wikidata_id": ent.wikidata_id,
        })

    # Add explicit relationships as edges
    relationships = session.query(EntityRelationship).all()
    for rel in relationships:
        G.add_edge(rel.source_entity_id, rel.target_entity_id, **{
            "type": rel.relationship_type,
            "confidence": rel.confidence,
        })

    # Add co-occurrence edges from events
    event_entities = session.query(EventEntity).all()
    event_groups: dict[int, list[int]] = {}
    for ee in event_entities:
        event_groups.setdefault(ee.event_id, []).append(ee.entity_id)

    for event_id, entity_ids in event_groups.items():
        for i in range(len(entity_ids)):
            for j in range(i + 1, len(entity_ids)):
                a, b = entity_ids[i], entity_ids[j]
                if G.has_edge(a, b):
                    G[a][b]["weight"] = G[a][b].get("weight", 1) + 1
                else:
                    G.add_edge(a, b, type="co_occurrence", weight=1)

    logger.info(f"Built graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


# ---------------------------------------------------------------------------
# Basic queries
# ---------------------------------------------------------------------------

def n_hop_neighbors(G: nx.DiGraph, entity_id: int, n: int = 2) -> dict:
    """Get all entities within N hops of the given entity."""
    if entity_id not in G:
        return {"center": entity_id, "neighbors": []}

    # BFS up to n hops
    visited = {entity_id}
    frontier = {entity_id}
    layers = []

    for hop in range(n):
        next_frontier = set()
        for node in frontier:
            for neighbor in set(G.successors(node)) | set(G.predecessors(node)):
                if neighbor not in visited:
                    visited.add(neighbor)
                    next_frontier.add(neighbor)
        if not next_frontier:
            break
        layers.append([
            {
                "id": nid,
                "name": G.nodes[nid].get("name", ""),
                "type": G.nodes[nid].get("type", ""),
                "hop": hop + 1,
            }
            for nid in next_frontier
        ])
        frontier = next_frontier

    return {
        "center": {
            "id": entity_id,
            "name": G.nodes[entity_id].get("name", ""),
            "type": G.nodes[entity_id].get("type", ""),
        },
        "layers": layers,
    }


def shortest_path(G: nx.DiGraph, source_id: int, target_id: int) -> list[dict] | None:
    """Find shortest path between two entities."""
    try:
        undirected = G.to_undirected()
        path = nx.shortest_path(undirected, source_id, target_id)
        return [
            {
                "id": nid,
                "name": G.nodes[nid].get("name", ""),
                "type": G.nodes[nid].get("type", ""),
            }
            for nid in path
        ]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def ego_graph(G: nx.DiGraph, entity_id: int, radius: int = 2) -> dict:
    """Get ego graph (subgraph centered on entity) for visualization."""
    if entity_id not in G:
        return {"nodes": [], "edges": []}

    undirected = G.to_undirected()
    ego = nx.ego_graph(undirected, entity_id, radius=radius)

    nodes = [
        {
            "id": nid,
            "name": G.nodes[nid].get("name", ""),
            "type": G.nodes[nid].get("type", ""),
        }
        for nid in ego.nodes
    ]

    edges = []
    for u, v, data in ego.edges(data=True):
        edges.append({
            "source": u,
            "target": v,
            "type": data.get("type", "unknown"),
            "weight": data.get("weight", 1),
        })

    return {"nodes": nodes, "edges": edges}


def top_connected_entities(G: nx.DiGraph, n: int = 20) -> list[dict]:
    """Get the most connected entities by degree centrality."""
    if G.number_of_nodes() == 0:
        return []

    centrality = nx.degree_centrality(G)
    sorted_entities = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:n]

    return [
        {
            "id": nid,
            "name": G.nodes[nid].get("name", ""),
            "type": G.nodes[nid].get("type", ""),
            "centrality": score,
            "degree": G.degree(nid),
        }
        for nid, score in sorted_entities
    ]


# ---------------------------------------------------------------------------
# Advanced analysis
# ---------------------------------------------------------------------------

def detect_communities(G: nx.DiGraph) -> list[dict]:
    """Detect communities using the Louvain algorithm.

    Converts the directed graph to undirected for community detection, then
    labels each community by the most connected entity within it.

    Returns a list of community dicts sorted by size descending.
    """
    if G.number_of_nodes() == 0:
        return []

    undirected = G.to_undirected()
    communities = louvain_communities(undirected, seed=42)

    results: list[dict] = []
    for idx, community_nodes in enumerate(communities):
        # Find the most connected node in this community to use as label
        subgraph = undirected.subgraph(community_nodes)
        if len(community_nodes) > 0:
            most_connected = max(community_nodes, key=lambda n: subgraph.degree(n))
            label = G.nodes[most_connected].get("name", f"Community {idx}")
        else:
            label = f"Community {idx}"

        entities = [
            {
                "id": nid,
                "name": G.nodes[nid].get("name", ""),
                "type": G.nodes[nid].get("type", ""),
            }
            for nid in sorted(community_nodes)
        ]

        results.append({
            "community_id": idx,
            "entities": entities,
            "size": len(community_nodes),
            "label": label,
        })

    # Sort by size descending
    results.sort(key=lambda c: c["size"], reverse=True)
    return results


def compute_centrality_scores(G: nx.DiGraph) -> list[dict]:
    """Compute multi-metric centrality scores for all nodes.

    Metrics computed:
    - Degree centrality
    - Betweenness centrality (identifies brokers/bridges)
    - Eigenvector centrality (influence via connections to influential nodes)
    - PageRank

    Returns a list of node dicts sorted by PageRank descending.
    """
    if G.number_of_nodes() == 0:
        return []

    degree = nx.degree_centrality(G)
    betweenness = nx.betweenness_centrality(G, weight="weight")
    pagerank = nx.pagerank(G, weight="weight")

    # Eigenvector centrality can fail to converge on some graphs; fall back to
    # zeros if that happens.
    try:
        eigenvector = nx.eigenvector_centrality(
            G, max_iter=1000, weight="weight",
        )
    except nx.PowerIterationFailedConvergence:
        logger.warning("Eigenvector centrality failed to converge; using zeros.")
        eigenvector = {n: 0.0 for n in G.nodes}

    results: list[dict] = []
    for nid in G.nodes:
        results.append({
            "id": nid,
            "name": G.nodes[nid].get("name", ""),
            "type": G.nodes[nid].get("type", ""),
            "degree": round(degree.get(nid, 0.0), 6),
            "betweenness": round(betweenness.get(nid, 0.0), 6),
            "eigenvector": round(eigenvector.get(nid, 0.0), 6),
            "pagerank": round(pagerank.get(nid, 0.0), 6),
        })

    results.sort(key=lambda r: r["pagerank"], reverse=True)
    return results


def infer_transitive_relationships(G: nx.DiGraph) -> list[dict]:
    """Infer transitive relationships from two-hop paths and co-occurrence.

    Uses ``TRANSITIVE_RULES`` to map (rel_type_1, rel_type_2) pairs along
    A->B->C paths to an inferred relationship type between A and C.

    Also infers ``co_occurrence_strong`` when two entities share 3 or more
    co-occurrence edges (weight >= threshold).

    Returns a list of inferred relationship dicts.
    """
    inferred: list[dict] = []
    seen: set[tuple] = set()

    # --- Rule-based transitive inference over two-hop directed paths ---
    for a in G.nodes:
        for b in G.successors(a):
            rel_ab = G[a][b].get("type", "")
            if not rel_ab or rel_ab == "co_occurrence":
                continue
            for c in G.successors(b):
                if c == a:
                    continue
                rel_bc = G[b][c].get("type", "")
                if not rel_bc or rel_bc == "co_occurrence":
                    continue
                key = (rel_ab, rel_bc)
                if key in TRANSITIVE_RULES:
                    inferred_type = TRANSITIVE_RULES[key]
                    dedup_key = (a, c, inferred_type)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # Confidence is product of the two edge confidences
                    conf_ab = G[a][b].get("confidence", 1.0)
                    conf_bc = G[b][c].get("confidence", 1.0)
                    confidence = round(conf_ab * conf_bc, 4)

                    name_a = G.nodes[a].get("name", str(a))
                    name_b = G.nodes[b].get("name", str(b))
                    name_c = G.nodes[c].get("name", str(c))

                    inferred.append({
                        "source": name_a,
                        "target": name_c,
                        "inferred_relationship": inferred_type,
                        "via": name_b,
                        "confidence": confidence,
                    })

    # --- Co-occurrence strength inference ---
    co_occurrence_counts: Counter[tuple[int, int]] = Counter()
    for u, v, data in G.edges(data=True):
        if data.get("type") == "co_occurrence":
            pair = (min(u, v), max(u, v))
            co_occurrence_counts[pair] += data.get("weight", 1)

    for (a, b), weight in co_occurrence_counts.items():
        if weight >= CO_OCCURRENCE_STRONG_THRESHOLD:
            dedup_key = (a, b, "co_occurrence_strong")
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            name_a = G.nodes[a].get("name", str(a))
            name_b = G.nodes[b].get("name", str(b))

            inferred.append({
                "source": name_a,
                "target": name_b,
                "inferred_relationship": "co_occurrence_strong",
                "via": f"{weight} shared events",
                "confidence": round(min(1.0, weight / 10.0), 4),
            })

    # Sort by confidence descending
    inferred.sort(key=lambda r: r["confidence"], reverse=True)
    return inferred


def temporal_graph_evolution(
    session: Session,
    G_builder_func: Callable[[Session], nx.DiGraph],
    windows: list[tuple[datetime, datetime]],
) -> list[dict]:
    """Track how the entity graph changes across time windows.

    For each ``(start, end)`` window, a subgraph is built from entities that
    appear in events whose ``first_reported_at`` falls within the window.
    Metrics are computed for each window and deltas (new / disappeared nodes)
    are tracked relative to the previous window.

    Parameters
    ----------
    session:
        Active SQLAlchemy session.
    G_builder_func:
        Callable that builds the full graph (typically ``build_entity_graph``).
    windows:
        Ordered list of ``(start, end)`` datetime tuples.

    Returns
    -------
    List of dicts with per-window metrics.
    """
    # Build full graph once for node attribute look-ups
    full_graph = G_builder_func(session)

    results: list[dict] = []
    prev_node_names: set[str] = set()

    for window_start, window_end in windows:
        # Find events in this window
        events_in_window = (
            session.query(Event)
            .filter(
                Event.first_reported_at >= window_start,
                Event.first_reported_at < window_end,
            )
            .all()
        )
        event_ids = {e.id for e in events_in_window}

        if not event_ids:
            results.append({
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "nodes": 0,
                "edges": 0,
                "density": 0.0,
                "new_entities": [],
                "gone_entities": sorted(prev_node_names),
            })
            prev_node_names = set()
            continue

        # Collect entity IDs that appear in those events
        event_entity_rows = (
            session.query(EventEntity)
            .filter(EventEntity.event_id.in_(event_ids))
            .all()
        )
        entity_ids = {ee.entity_id for ee in event_entity_rows}

        # Build subgraph from full graph
        valid_ids = entity_ids & set(full_graph.nodes)
        subgraph = full_graph.subgraph(valid_ids).copy()

        current_node_names = {
            full_graph.nodes[nid].get("name", str(nid))
            for nid in subgraph.nodes
        }

        new_entities = sorted(current_node_names - prev_node_names)
        gone_entities = sorted(prev_node_names - current_node_names)

        n_nodes = subgraph.number_of_nodes()
        n_edges = subgraph.number_of_edges()
        density = nx.density(subgraph) if n_nodes > 1 else 0.0

        results.append({
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "nodes": n_nodes,
            "edges": n_edges,
            "density": round(density, 6),
            "new_entities": new_entities,
            "gone_entities": gone_entities,
        })

        prev_node_names = current_node_names

    return results


def find_key_brokers(G: nx.DiGraph, n: int = 10) -> list[dict]:
    """Find entities that bridge otherwise disconnected communities.

    Combines betweenness centrality with articulation-point detection on the
    undirected projection.  For each candidate the number of distinct Louvain
    communities it connects is also reported.

    Returns the top *n* brokers sorted by betweenness descending.
    """
    if G.number_of_nodes() == 0:
        return []

    betweenness = nx.betweenness_centrality(G, weight="weight")

    # Articulation points only defined for undirected graphs
    undirected = G.to_undirected()
    articulation_points = set(nx.articulation_points(undirected))

    # Build community map for counting bridged communities
    communities = louvain_communities(undirected, seed=42)
    node_to_community: dict[int, int] = {}
    for idx, community_nodes in enumerate(communities):
        for nid in community_nodes:
            node_to_community[nid] = idx

    results: list[dict] = []
    for nid in G.nodes:
        # Count how many distinct communities this node's neighbors belong to
        neighbor_communities: set[int] = set()
        for neighbor in set(G.successors(nid)) | set(G.predecessors(nid)):
            comm = node_to_community.get(neighbor)
            if comm is not None:
                neighbor_communities.add(comm)

        results.append({
            "id": nid,
            "name": G.nodes[nid].get("name", ""),
            "type": G.nodes[nid].get("type", ""),
            "betweenness": round(betweenness.get(nid, 0.0), 6),
            "is_articulation_point": nid in articulation_points,
            "communities_bridged": len(neighbor_communities),
        })

    # Sort by betweenness descending, take top n
    results.sort(key=lambda r: r["betweenness"], reverse=True)
    return results[:n]


def export_graph_json(G: nx.DiGraph) -> dict:
    """Export the full graph as vis.js-compatible JSON.

    Returns a dict with ``nodes`` and ``edges`` lists ready for rendering in
    a vis.js Network visualization.

    Node size is scaled by degree; edge width is scaled by weight.
    """
    # Compute degree for sizing
    degrees = dict(G.degree())
    max_degree = max(degrees.values()) if degrees else 1

    nodes: list[dict] = []
    for nid, data in G.nodes(data=True):
        deg = degrees.get(nid, 0)
        # Scale node size between 10 and 50 based on degree
        size = 10 + (40 * deg / max_degree) if max_degree > 0 else 10
        nodes.append({
            "id": nid,
            "label": data.get("name", str(nid)),
            "group": data.get("type", "unknown"),
            "size": round(size, 1),
        })

    edges: list[dict] = []
    for u, v, data in G.edges(data=True):
        weight = data.get("weight", 1)
        # Scale edge width between 1 and 8
        width = max(1, min(8, weight))
        edges.append({
            "from": u,
            "to": v,
            "label": data.get("type", ""),
            "width": width,
        })

    return {"nodes": nodes, "edges": edges}
