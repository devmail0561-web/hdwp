# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hdwp.core.model.schemas import ApplicationModelData, DBColumn, DBTable


_ENTITY_VOCAB = {
    "user", "account", "customer", "client", "person",
    "product", "item", "article", "post", "content",
    "order", "cart", "invoice", "payment", "transaction",
    "session", "token", "auth", "permission", "role",
    "file", "image", "document", "attachment",
    "comment", "message", "notification",
    "category", "tag", "label",
    "address", "location", "country",
}


def _to_snake(name: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower().replace("-", "_").replace(" ", "_")


def _extract_entity(name: str) -> str | None:
    normalized = _to_snake(name).lower()
    parts = [p for p in normalized.replace("-", "_").split("_") if p]
    for entity in _ENTITY_VOCAB:
        if entity in parts:
            return entity
    return None


class DBInferrer:
    """Infers relational database table structure from observed API parameters and response schemas."""

    def infer(self, model: ApplicationModelData) -> list[DBTable]:
        from hdwp.core.model.schemas import DBColumn, DBTable

        entity_columns: dict[str, list[DBColumn]] = defaultdict(list)
        entity_endpoints: dict[str, set[str]] = defaultdict(set)
        seen_cols: dict[str, set[str]] = defaultdict(set)

        # Step 1: Parameters → entities
        for param in model.parameters:
            entity = _extract_entity(param.name)
            if not entity:
                continue
            col_name = _to_snake(param.name)
            if col_name in seen_cols[entity]:
                continue
            seen_cols[entity].add(col_name)
            is_pk = col_name in ("id", f"{entity}_id") and param.type_inferred in ("integer", "uuid")
            entity_columns[entity].append(DBColumn(
                name=col_name,
                type_hint=param.type_inferred,
                is_pk=is_pk,
            ))
            for ep in model.endpoints:
                if param.id in ep.parameters:
                    entity_endpoints[entity].add(ep.path)

        # Step 2: DataObject schemas → additional columns
        for obj in model.objects:
            for field_name, type_name in obj.schema_def.items():
                entity = _extract_entity(field_name)
                if not entity:
                    continue
                col_name = _to_snake(field_name)
                if col_name in seen_cols[entity]:
                    continue
                seen_cols[entity].add(col_name)
                entity_columns[entity].append(DBColumn(name=col_name, type_hint=type_name))

        # Step 3: FK detection
        all_entities = set(entity_columns.keys())
        for entity, columns in entity_columns.items():
            for col in columns:
                for other in all_entities - {entity}:
                    if col.name in (f"{other}_id", f"{other}id"):
                        other_table = other + "s" if not other.endswith("s") else other
                        col.is_fk_to = f"{other_table}.id"
                        break

        # Step 4: Build tables with confidence threshold
        tables: list[DBTable] = []
        total_endpoints = max(len(model.endpoints), 1)
        for entity, columns in entity_columns.items():
            if not columns:
                continue
            endpoints = list(entity_endpoints.get(entity, set()))
            confidence = min(0.9, len(endpoints) / total_endpoints * 3)
            if confidence >= 0.15:
                table_name = entity + "s" if not entity.endswith("s") else entity
                tables.append(DBTable(
                    name=table_name,
                    columns=columns[:15],
                    evidence_endpoints=endpoints[:5],
                    confidence=round(confidence, 3),
                ))

        return sorted(tables, key=lambda t: -t.confidence)
