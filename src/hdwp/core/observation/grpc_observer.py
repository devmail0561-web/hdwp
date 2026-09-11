# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from hdwp.core.bus.event_bus import AsyncEventBus
from hdwp.core.bus.events import OBSERVATION_RAW
from hdwp.core.model.schemas import (
    NormalizedResponse,
    ObservationType,
    RawObservation,
)

log = structlog.get_logger()

try:
    import grpc
    import grpc.aio
    from grpc_reflection.v1alpha.proto_reflection_descriptor_database import (
        ProtoReflectionDescriptorDatabase,
    )

    _HAS_GRPC = True
except ImportError:
    _HAS_GRPC = False


class GrpcObserver:
    def __init__(
        self,
        bus: AsyncEventBus,
        session_id: str,
    ) -> None:
        self._bus = bus
        self._session_id = session_id

    async def observe(
        self,
        target: str,
        tls: bool = False,
        proto_files: list[str] | None = None,
    ) -> None:
        if not _HAS_GRPC:
            log.debug("grpc_observer.skipped", reason="grpcio not installed")
            return

        if proto_files:
            await self._observe_from_proto(target, proto_files)
            return

        creds = grpc.ssl_channel_credentials() if tls else None
        channel = (
            grpc.aio.secure_channel(target, creds)
            if tls
            else grpc.aio.insecure_channel(target)
        )
        try:
            await self._observe_via_reflection(channel, target, tls)
        except grpc.RpcError:
            await self._emit_no_reflection(target, tls)
        finally:
            await channel.close()

    async def _observe_via_reflection(
        self,
        channel: Any,
        target: str,
        tls: bool,
    ) -> None:
        reflection_db = ProtoReflectionDescriptorDatabase(channel)
        services = reflection_db.get_services()
        for svc in services:
            if svc == "grpc.reflection.v1alpha.ServerReflection":
                continue
            methods = self._list_methods(reflection_db, svc)
            obs = RawObservation(
                timestamp=datetime.now(UTC).isoformat(),
                source="active",
                type=ObservationType.GRPC,
                session_id=self._session_id,
                response=NormalizedResponse(status_code=200),
                artefact={
                    "service": svc,
                    "methods": methods,
                    "target": target,
                    "tls": tls,
                },
            )
            await self._bus.emit(
                OBSERVATION_RAW, obs.model_dump(), source="grpc_observer",
            )

    @staticmethod
    def _list_methods(reflection_db: Any, service_name: str) -> list[dict[str, str]]:
        methods: list[dict[str, str]] = []
        try:
            from google.protobuf import descriptor_pool

            pool = descriptor_pool.DescriptorPool()
            reflection_db.FindFileContainingSymbol(service_name)
            svc_desc = pool.FindServiceByName(service_name)
            for m in svc_desc.methods:
                methods.append({
                    "name": m.name,
                    "input_type": m.input_type.full_name,
                    "output_type": m.output_type.full_name,
                })
        except Exception:
            methods.append({"name": service_name, "input_type": "unknown", "output_type": "unknown"})
        return methods

    async def _emit_no_reflection(self, target: str, tls: bool) -> None:
        log.debug("grpc_observer.no_reflection", target=target)
        obs = RawObservation(
            timestamp=datetime.now(UTC).isoformat(),
            source="active",
            type=ObservationType.GRPC,
            session_id=self._session_id,
            response=NormalizedResponse(status_code=200),
            artefact={
                "target": target,
                "tls": tls,
                "service": "unknown",
                "methods": [],
            },
            tags=["grpc:no_reflection"],
        )
        await self._bus.emit(
            OBSERVATION_RAW, obs.model_dump(), source="grpc_observer",
        )

    async def _observe_from_proto(
        self, target: str, proto_files: list[str],
    ) -> None:
        for proto_path in proto_files:
            try:
                from google.protobuf import descriptor_pb2
                from google.protobuf.compiler import plugin_pb2  # noqa: F401

                with open(proto_path, "r") as f:
                    content = f.read()

                services = _extract_services_from_proto(content)
                for svc_name, methods in services.items():
                    obs = RawObservation(
                        timestamp=datetime.now(UTC).isoformat(),
                        source="active",
                        type=ObservationType.GRPC,
                        session_id=self._session_id,
                        response=NormalizedResponse(status_code=200),
                        artefact={
                            "service": svc_name,
                            "methods": methods,
                            "target": target,
                            "proto_file": proto_path,
                        },
                        tags=["grpc:from_proto"],
                    )
                    await self._bus.emit(
                        OBSERVATION_RAW, obs.model_dump(), source="grpc_observer",
                    )
            except Exception as exc:
                log.debug(
                    "grpc_observer.proto_parse_failed",
                    path=proto_path,
                    error=str(exc),
                )


def _extract_services_from_proto(content: str) -> dict[str, list[dict[str, str]]]:
    import re

    services: dict[str, list[dict[str, str]]] = {}
    svc_pattern = re.compile(r"service\s+(\w+)\s*\{([^}]*)\}", re.DOTALL)
    rpc_pattern = re.compile(
        r"rpc\s+(\w+)\s*\(\s*(\w+)\s*\)\s*returns\s*\(\s*(\w+)\s*\)"
    )
    for svc_match in svc_pattern.finditer(content):
        svc_name = svc_match.group(1)
        body = svc_match.group(2)
        methods = []
        for rpc_match in rpc_pattern.finditer(body):
            methods.append({
                "name": rpc_match.group(1),
                "input_type": rpc_match.group(2),
                "output_type": rpc_match.group(3),
            })
        services[svc_name] = methods
    return services
