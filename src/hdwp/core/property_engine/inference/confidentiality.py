# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from hdwp.core.model.schemas import (
    ApplicationModelData,
    PropertyType,
    SecurityProperty,
    generate_id,
)


class ConfidentialityInference:
    """Infers confidentiality properties from the application model."""

    def infer(self, model: ApplicationModelData) -> list[SecurityProperty]:
        properties: list[SecurityProperty] = []

        for obj in model.objects:
            if obj.sensitivity in ("private", "sensitive") and obj.owner_parameter:
                properties.append(
                    SecurityProperty(
                        id=generate_id("PROP"),
                        type=PropertyType.CONFIDENTIALITY,
                        formal_statement=(
                            f"query(A, object:{obj.id}) => owner(object) = A"
                        ),
                        model_nodes=[obj.id],
                        inference_confidence=0.7,
                        source_observations=[],
                    )
                )

        return properties
