"""Structured evidence graph for DFIR investigation."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import json
import logging

logger = logging.getLogger(__name__)


class EntityType(str, Enum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    HASH = "hash"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    AUTH_EVENT = "authentication_event"
    NETWORK_CONN = "network_connection"
    SERVICE = "service"
    REGISTRY = "registry_artifact"
    ALERT = "alert"
    TIMESTAMP_EVENT = "timestamp_event"


class RelationshipType(str, Enum):
    PARENT_OF = "parent_of"
    SPAWNED = "spawned"
    EXECUTED = "executed"
    ACCESSED = "accessed"
    CREATED = "created"
    MODIFIED = "modified"
    CONNECTED_TO = "connected_to"
    AUTHENTICATED_TO = "authenticated_to"
    DOWNLOADED = "downloaded"
    RESOLVED = "resolved"
    PERSISTED_VIA = "persisted_via"
    OBSERVED_ON = "observed_on"
    ASSOCIATED_WITH = "associated_with"


@dataclass
class EvidenceEntity:
    entity_id: str
    entity_type: EntityType
    properties: Dict[str, Any] = field(default_factory=dict)
    source_event_ids: List[str] = field(default_factory=list)
    timestamps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value if isinstance(self.entity_type, EntityType) else str(self.entity_type),
            "properties": self.properties,
            "source_event_ids": list(set(self.source_event_ids)),
            "timestamps": sorted(list(set(self.timestamps))),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceEntity:
        entity_type_val = data.get("entity_type", "process")
        try:
            etype = EntityType(entity_type_val)
        except ValueError:
            etype = EntityType.PROCESS

        return cls(
            entity_id=str(data["entity_id"]),
            entity_type=etype,
            properties=dict(data.get("properties", {})),
            source_event_ids=list(data.get("source_event_ids", [])),
            timestamps=list(data.get("timestamps", [])),
        )


@dataclass
class EvidenceEdge:
    source_id: str
    target_id: str
    relationship: RelationshipType
    source_event_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_telemetry: Optional[str] = None
    confidence: float = 1.0
    original_reference: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship.value if isinstance(self.relationship, RelationshipType) else str(self.relationship),
            "source_event_id": self.source_event_id,
            "timestamp": self.timestamp,
            "source_telemetry": self.source_telemetry,
            "confidence": self.confidence,
            "original_reference": self.original_reference,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceEdge:
        rel_val = data.get("relationship", "associated_with")
        try:
            rel = RelationshipType(rel_val)
        except ValueError:
            rel = RelationshipType.ASSOCIATED_WITH

        return cls(
            source_id=str(data["source_id"]),
            target_id=str(data["target_id"]),
            relationship=rel,
            source_event_id=data.get("source_event_id"),
            timestamp=data.get("timestamp"),
            source_telemetry=data.get("source_telemetry"),
            confidence=float(data.get("confidence", 1.0)),
            original_reference=data.get("original_reference"),
        )


class EvidenceGraph:
    """Graph of entities, relationships, and timeline events discovered during investigation."""

    def __init__(self):
        self.entities: Dict[str, EvidenceEntity] = {}
        self.edges: List[EvidenceEdge] = []
        self.timeline: List[Dict[str, Any]] = []

    def add_entity(self, entity: EvidenceEntity) -> None:
        """Add or merge an entity into the graph."""
        if entity.entity_id in self.entities:
            existing = self.entities[entity.entity_id]
            # Merge properties
            existing.properties.update(entity.properties)
            # Merge event IDs
            existing.source_event_ids = list(set(existing.source_event_ids + entity.source_event_ids))
            # Merge timestamps
            existing.timestamps = sorted(list(set(existing.timestamps + entity.timestamps)))
        else:
            self.entities[entity.entity_id] = entity

    def get_entity(self, entity_id: str) -> Optional[EvidenceEntity]:
        return self.entities.get(entity_id)

    def add_edge(self, edge: EvidenceEdge) -> None:
        """Add edge if not duplicate (source, target, relationship match)."""
        for existing in self.edges:
            if (
                existing.source_id == edge.source_id
                and existing.target_id == edge.target_id
                and existing.relationship == edge.relationship
            ):
                # Update metadata if available
                if not existing.source_event_id and edge.source_event_id:
                    existing.source_event_id = edge.source_event_id
                if not existing.timestamp and edge.timestamp:
                    existing.timestamp = edge.timestamp
                return
        self.edges.append(edge)

    def get_entity_edges(self, entity_id: str) -> List[EvidenceEdge]:
        """Get all incoming and outgoing edges for an entity."""
        return [e for e in self.edges if e.source_id == entity_id or e.target_id == entity_id]

    def get_neighbors(self, entity_id: str) -> List[EvidenceEntity]:
        """Get all entities connected to the given entity."""
        neighbor_ids: Set[str] = set()
        for edge in self.edges:
            if edge.source_id == entity_id:
                neighbor_ids.add(edge.target_id)
            elif edge.target_id == entity_id:
                neighbor_ids.add(edge.source_id)
        return [self.entities[nid] for nid in neighbor_ids if nid in self.entities]

    def add_timeline_event(
        self,
        timestamp: str,
        event_id: str,
        description: str,
        entity_ids: Optional[List[str]] = None,
        event_type: Optional[str] = None,
    ) -> None:
        """Add an event to the chronological timeline."""
        if not timestamp:
            return

        # Avoid exact duplicates
        for existing in self.timeline:
            if existing.get("event_id") == event_id and existing.get("timestamp") == timestamp:
                return

        event_record = {
            "timestamp": timestamp,
            "event_id": event_id,
            "description": description,
            "entity_ids": entity_ids or [],
            "event_type": event_type or "general",
        }
        self.timeline.append(event_record)
        # Keep timeline sorted
        self.timeline.sort(key=lambda x: str(x.get("timestamp", "")))

    def get_timeline(self) -> List[Dict[str, Any]]:
        return list(self.timeline)

    def detect_temporal_anomalies(self) -> List[Dict[str, Any]]:
        """Detect temporal anomalies:
        - Parent process spawned after child process
        - Events out of plausible sequential order
        - Extreme time gaps between tightly coupled attack actions
        """
        anomalies: List[Dict[str, Any]] = []

        # 1. Process parent/child timestamp anomalies
        for edge in self.edges:
            if edge.relationship in (RelationshipType.PARENT_OF, RelationshipType.SPAWNED):
                parent = self.entities.get(edge.source_id)
                child = self.entities.get(edge.target_id)
                if parent and child:
                    parent_ts = parent.properties.get("start_time") or parent.properties.get("timestamp")
                    child_ts = child.properties.get("start_time") or child.properties.get("timestamp")
                    if parent_ts and child_ts:
                        try:
                            p_dt = datetime.fromisoformat(parent_ts.replace("Z", "+00:00"))
                            c_dt = datetime.fromisoformat(child_ts.replace("Z", "+00:00"))
                            if p_dt > c_dt:
                                anomalies.append({
                                    "type": "impossible_parent_child_timing",
                                    "description": f"Parent {parent.entity_id} timestamp ({parent_ts}) is later than child {child.entity_id} timestamp ({child_ts})",
                                    "entities": [parent.entity_id, child.entity_id],
                                    "severity": "HIGH",
                                })
                        except (ValueError, TypeError):
                            pass

        # 2. Timeline sequence checks (e.g. negative timestamp diffs if sorting failed)
        prev_dt = None
        for item in self.timeline:
            ts_str = item.get("timestamp")
            if not ts_str:
                continue
            try:
                curr_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if prev_dt and curr_dt < prev_dt:
                    anomalies.append({
                        "type": "out_of_order_timeline",
                        "description": f"Timeline event {item.get('event_id')} has timestamp {ts_str} prior to preceding event",
                        "event_id": item.get("event_id"),
                        "severity": "MEDIUM",
                    })
                prev_dt = curr_dt
            except (ValueError, TypeError):
                pass

        return anomalies

    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> List[str]:
        """Find a path between two entities in the graph (BFS)."""
        if source_id not in self.entities or target_id not in self.entities:
            return []
        if source_id == target_id:
            return [source_id]

        visited: Set[str] = {source_id}
        queue: List[List[str]] = [[source_id]]

        while queue:
            path = queue.pop(0)
            if len(path) > max_depth:
                continue
            node = path[-1]
            for neighbor in self.get_neighbors(node):
                nid = neighbor.entity_id
                if nid == target_id:
                    return path + [nid]
                if nid not in visited:
                    visited.add(nid)
                    queue.append(path + [nid])
        return []

    def ingest_tool_result(self, tool_name: str, tool_args: Dict[str, Any], result: Any) -> None:
        """Parse structured items from tool results into entities, edges, and timeline events."""
        if not result:
            return

        # If result is string or dict, parse if needed
        data = result
        if isinstance(result, str):
            try:
                data = json.loads(result)
            except Exception:
                return

        # Handle list of items or single item
        items = data if isinstance(data, list) else [data]

        for item in items:
            if not isinstance(item, dict):
                continue

            event_id = item.get("event_id") or item.get("id")
            timestamp = item.get("timestamp") or item.get("start_time") or item.get("created_time")
            hostname = item.get("hostname") or item.get("host_name") or item.get("computer_name")
            user = item.get("user") or item.get("username") or item.get("user_name")

            # Ingest Host
            if hostname:
                host_id = f"host-{hostname.lower()}"
                self.add_entity(
                    EvidenceEntity(
                        entity_id=host_id,
                        entity_type=EntityType.HOST,
                        properties={"hostname": hostname},
                        source_event_ids=[event_id] if event_id else [],
                        timestamps=[timestamp] if timestamp else [],
                    )
                )

            # Ingest User
            if user:
                user_id = f"user-{user.lower()}"
                self.add_entity(
                    EvidenceEntity(
                        entity_id=user_id,
                        entity_type=EntityType.USER,
                        properties={"username": user},
                        source_event_ids=[event_id] if event_id else [],
                        timestamps=[timestamp] if timestamp else [],
                    )
                )
                if hostname:
                    self.add_edge(
                        EvidenceEdge(
                            source_id=user_id,
                            target_id=f"host-{hostname.lower()}",
                            relationship=RelationshipType.OBSERVED_ON,
                            source_event_id=event_id,
                            timestamp=timestamp,
                        )
                    )

            # Ingest Process
            proc_id = item.get("process_id") or item.get("process_entity_id")
            proc_name = item.get("process_name") or item.get("image_path") or item.get("name")
            cmdline = item.get("command_line") or item.get("cmdline")
            parent_id = item.get("parent_process_id") or item.get("parent_process_entity_id")

            if proc_id or (proc_name and event_id):
                entity_pid = str(proc_id) if proc_id else f"proc-{event_id}"
                self.add_entity(
                    EvidenceEntity(
                        entity_id=entity_pid,
                        entity_type=EntityType.PROCESS,
                        properties={
                            "process_name": proc_name,
                            "command_line": cmdline,
                            "pid": item.get("pid"),
                            "parent_pid": item.get("parent_pid"),
                            "timestamp": timestamp,
                        },
                        source_event_ids=[event_id] if event_id else [],
                        timestamps=[timestamp] if timestamp else [],
                    )
                )
                if hostname:
                    self.add_edge(
                        EvidenceEdge(
                            source_id=entity_pid,
                            target_id=f"host-{hostname.lower()}",
                            relationship=RelationshipType.OBSERVED_ON,
                            source_event_id=event_id,
                            timestamp=timestamp,
                        )
                    )
                if parent_id:
                    parent_entity_id = str(parent_id)
                    # Add edge parent -> child
                    self.add_edge(
                        EvidenceEdge(
                            source_id=parent_entity_id,
                            target_id=entity_pid,
                            relationship=RelationshipType.PARENT_OF,
                            source_event_id=event_id,
                            timestamp=timestamp,
                        )
                    )

            # Ingest Network Connections
            dest_ip = item.get("destination_ip") or item.get("dest_ip") or item.get("remote_ip")
            dest_port = item.get("destination_port") or item.get("dest_port") or item.get("remote_port")
            if dest_ip:
                ip_id = f"ip-{dest_ip}"
                self.add_entity(
                    EvidenceEntity(
                        entity_id=ip_id,
                        entity_type=EntityType.IP_ADDRESS,
                        properties={"ip": dest_ip, "port": dest_port},
                        source_event_ids=[event_id] if event_id else [],
                        timestamps=[timestamp] if timestamp else [],
                    )
                )
                if proc_id:
                    self.add_edge(
                        EvidenceEdge(
                            source_id=str(proc_id),
                            target_id=ip_id,
                            relationship=RelationshipType.CONNECTED_TO,
                            source_event_id=event_id,
                            timestamp=timestamp,
                        )
                    )

            # Ingest Files
            file_path = item.get("file_path") or item.get("target_filename") or item.get("path")
            file_hash = item.get("hash") or item.get("sha256") or item.get("md5")
            if file_path:
                file_id = f"file-{file_path.lower()}"
                self.add_entity(
                    EvidenceEntity(
                        entity_id=file_id,
                        entity_type=EntityType.FILE,
                        properties={"file_path": file_path, "hash": file_hash},
                        source_event_ids=[event_id] if event_id else [],
                        timestamps=[timestamp] if timestamp else [],
                    )
                )
                if proc_id:
                    action = (item.get("event_type") or item.get("action") or "").lower()
                    rel = RelationshipType.CREATED if "create" in action else RelationshipType.ACCESSED
                    self.add_edge(
                        EvidenceEdge(
                            source_id=str(proc_id),
                            target_id=file_id,
                            relationship=rel,
                            source_event_id=event_id,
                            timestamp=timestamp,
                        )
                    )

            # Ingest Timeline event
            if timestamp and event_id:
                desc = (
                    cmdline
                    or (f"{proc_name} accessed {file_path}" if file_path and proc_name else None)
                    or (f"{proc_name} connected to {dest_ip}:{dest_port}" if dest_ip and proc_name else None)
                    or item.get("description")
                    or item.get("event_type")
                    or f"Event {event_id}"
                )
                entity_ids = []
                if hostname:
                    entity_ids.append(f"host-{hostname.lower()}")
                if user:
                    entity_ids.append(f"user-{user.lower()}")
                if proc_id:
                    entity_ids.append(str(proc_id))
                if dest_ip:
                    entity_ids.append(f"ip-{dest_ip}")
                if file_path:
                    entity_ids.append(f"file-{file_path.lower()}")

                self.add_timeline_event(
                    timestamp=timestamp,
                    event_id=event_id,
                    description=desc,
                    entity_ids=entity_ids,
                    event_type=item.get("event_type"),
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entities": {k: v.to_dict() for k, v in self.entities.items()},
            "edges": [e.to_dict() for e in self.edges],
            "timeline": self.timeline,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceGraph:
        graph = cls()
        if not data:
            return graph

        entities_data = data.get("entities", {})
        for eid, edict in entities_data.items():
            graph.entities[eid] = EvidenceEntity.from_dict(edict)

        edges_data = data.get("edges", [])
        for edict in edges_data:
            graph.edges.append(EvidenceEdge.from_dict(edict))

        graph.timeline = list(data.get("timeline", []))
        return graph
